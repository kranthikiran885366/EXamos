#include "../include/vision_engine.h"

#include <opencv2/opencv.hpp>
#include <opencv2/dnn.hpp>
#include <opencv2/face.hpp>
#include <openssl/evp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <chrono>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

/*
 * Real detection.
 *
 * Every detector here reports what it actually matched, and nothing at all
 * when it matched nothing. Three classes of detector are supported, each
 * loaded from a digest-verified artefact named in the model manifest:
 *
 *   face-dnn     Caffe SSD face detector. Produces a calibrated detection
 *                score per face, so the reported confidence is a real
 *                score and not a placeholder.
 *   face-cascade OpenCV's frontal-face Haar cascade, which is bundled with
 *                the installed OpenCV package. A cascade yields no
 *                calibrated probability, so the confidence stays at zero.
 *   object-dnn   YOLOX-S (ONNX, Apache-2.0) trained on COCO. Provides the
 *                "cell phone" and "book" classes used by the taxonomy.
 *   landmarks    LBF 68-point facial landmark model, which makes head pose
 *                estimation possible; without it head pose is reported as
 *                unavailable rather than derived from unrelated measurements.
 *
 * The previous implementation inferred "one face, confidence 0.92" from
 * nothing more than the average luminance of the frame. That produced
 * fabricated evidence, so it was removed rather than tuned.
 */

namespace {

/* Artefact roles named by the model manifest. */
const char *ROLE_FACE_DNN_PROTOTXT   = "face-dnn-prototxt";
const char *ROLE_FACE_DNN_WEIGHTS     = "face-dnn-weights";
const char *ROLE_FACE_CASCADE         = "face-cascade";
const char *ROLE_OBJECT_DNN_PROTOTXT  = "object-dnn-prototxt";
const char *ROLE_OBJECT_DNN_WEIGHTS   = "object-dnn-weights";
const char *ROLE_LANDMARKS            = "landmarks";

/* COCO class identifiers used by the object detector.
 *
 * The YOLOv8 family uses the contiguous 0-79 COCO index, where 67 is
 * "cell phone" and 73 is "book".  (The 90-class COCO label map used by
 * TensorFlow models numbers the same classes 77 and 84; do not mix the two
 * maps - doing so makes the engine report a microwave as a phone.) */
const int COCO_CELL_PHONE = 67;
const int COCO_BOOK       = 73;

const float FACE_SCORE_THRESHOLD = 0.50f;
const float OBJECT_SCORE_THRESHOLD = 0.45f;
const float OBJECT_NMS_THRESHOLD = 0.45f;
const int   OBJECT_INPUT_SIZE = 640;

/* A model artefact named by the manifest. */
struct ModelArtifact {
    std::string role;
    std::string name;
    std::string path;
    std::string digest;
    std::string framework;
    bool        verified = false;
};

std::map<std::string, ModelArtifact> g_artifacts;

/* Extracts a quoted string field from a JSON fragment. */
bool json_field(const std::string &text, const std::string &key, std::string &out) {
    const std::string pattern = "\"" + key + "\"";
    size_t position = text.find(pattern);
    if (position == std::string::npos) return false;
    position += pattern.size();
    while (position < text.size() &&
           (text[position] == ' ' || text[position] == '\t' ||
            text[position] == '\n' || text[position] == '\r')) position++;
    if (position >= text.size() || text[position] != ':') return false;
    position++;
    while (position < text.size() &&
           (text[position] == ' ' || text[position] == '\t' ||
            text[position] == '\n' || text[position] == '\r')) position++;
    if (position >= text.size() || text[position] != '"') return false;
    position++;
    size_t end = text.find('"', position);
    if (end == std::string::npos) return false;
    out = text.substr(position, end - position);
    return true;
}

/* Reads a SHA-256 digest of a file into a 64-character hex string. */
bool file_digest(const std::string &path, std::string &digest_hex) {
    FILE *file = std::fopen(path.c_str(), "rb");
    if (!file) return false;
    if (std::fseek(file, 0, SEEK_END) != 0) { std::fclose(file); return false; }
    long size = std::ftell(file);
    if (size <= 0 || size > 256L * 1024L * 1024L) { std::fclose(file); return false; }
    std::rewind(file);

    std::vector<unsigned char> buffer(static_cast<size_t>(size));
    size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
    std::fclose(file);
    if (read != buffer.size()) return false;

    unsigned char digest[32];
    if (EVP_Digest(buffer.data(), buffer.size(), digest, nullptr, EVP_sha256(), nullptr) != 1) {
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    digest_hex.clear();
    for (int i = 0; i < 32; i++) {
        digest_hex.push_back(hex[digest[i] >> 4]);
        digest_hex.push_back(hex[digest[i] & 0x0F]);
    }
    return true;
}

/* Parses the model manifest and resolves every artefact it names. */
bool load_manifest(const char *config_path, std::map<std::string, ModelArtifact> &out) {
    if (!config_path || !config_path[0]) return false;

    FILE *file = std::fopen(config_path, "rb");
    if (!file) return false;
    std::string manifest;
    char buffer[4096];
    size_t read = 0;
    while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
        manifest.append(buffer, read);
    }
    std::fclose(file);
    if (manifest.empty()) return false;

    size_t models_position = manifest.find("\"models\"");
    if (models_position == std::string::npos) return false;
    size_t array_start = manifest.find('[', models_position);
    if (array_start == std::string::npos) return false;

    std::string manifest_dir(config_path);
    size_t slash = manifest_dir.find_last_of('/');
    manifest_dir = (slash == std::string::npos) ? std::string(".") : manifest_dir.substr(0, slash);

    size_t cursor = array_start + 1;
    while (true) {
        size_t object_start = manifest.find('{', cursor);
        if (object_start == std::string::npos) break;
        size_t object_end = manifest.find('}', object_start);
        if (object_end == std::string::npos) break;
        std::string block = manifest.substr(object_start, object_end - object_start + 1);

        ModelArtifact artifact;
        std::string file_name;
        if (json_field(block, "role", artifact.role) &&
            json_field(block, "file", file_name) && !file_name.empty()) {
            json_field(block, "name", artifact.name);
            json_field(block, "sha256", artifact.digest);
            json_field(block, "framework", artifact.framework);
            artifact.path = manifest_dir + "/" + file_name;
            out[artifact.role] = artifact;
        }
        cursor = object_end + 1;
    }
    return !out.empty();
}

/* Verifies one artefact against the digest recorded in the manifest. */
bool verify_artifact(const ModelArtifact &artifact) {
    if (artifact.digest.empty()) {
        fprintf(stderr,
                "[VisionEngine] FATAL: detector artefact '%s' has no approved digest in the manifest.\n",
                artifact.path.c_str());
        return false;
    }
    std::string actual;
    if (!file_digest(artifact.path, actual)) {
        fprintf(stderr, "[VisionEngine] FATAL: detector artefact '%s' is unreadable.\n",
                artifact.path.c_str());
        return false;
    }
    if (actual != artifact.digest) {
        fprintf(stderr,
                "[VisionEngine] FATAL: detector artefact '%s' does not match its approved digest.\n"
                "  expected %s\n  actual   %s\n",
                artifact.path.c_str(), artifact.digest.c_str(), actual.c_str());
        return false;
    }
    return true;
}

/* ---------------------------------------------------------------------
 * Detectors
 * --------------------------------------------------------------------- */

struct FaceDetection {
    cv::Rect box;
    float      score;
};

class FaceDetector {
public:
    virtual ~FaceDetector() {}
    virtual const char *scorer() const = 0;
    /* Whether this detector produces a calibrated detection score. A
       cascade yields presence and location only, so it does not. */
    virtual bool produces_confidence() const = 0;
    virtual std::vector<FaceDetection> detect(const cv::Mat &frame) = 0;
};

/* Caffe SSD face detector. Produces a calibrated score per detection. */
class SsdFaceDetector : public FaceDetector {
public:
    bool load(const std::string &prototxt, const std::string &weights) {
        try {
            net_ = cv::dnn::readNetFromCaffe(prototxt, weights);
        } catch (const cv::Exception &error) {
            fprintf(stderr, "[VisionEngine] Face detector could not be loaded: %s\n", error.what());
            return false;
        }
        loaded_ = true;
        return true;
    }
    const char *scorer() const override { return "opencv-dnn-ssd-face"; }
    bool produces_confidence() const override { return true; }
    std::vector<FaceDetection> detect(const cv::Mat &frame) override {
        std::vector<FaceDetection> found;
        if (!loaded_) return found;
        try {
            cv::Mat blob = cv::dnn::blobFromImage(frame, 1.0,
                                                  cv::Size(300, 300),
                                                  cv::Scalar(104.0, 177.0, 123.0));
            net_.setInput(blob);
            cv::Mat detections = net_.forward();
            for (int i = 0; i < detections.size[2]; ++i) {
                const float *row = detections.ptr<float>(0) + detections.step[2] * i;
                /* The res10 SSD face detector emits seven values per
                   detection: [image id, is-match, confidence, x, y, w, h].
                   The confidence and the box therefore start at index 2,
                   and the box is normalised to the input. */
                float score = row[2];
                if (score < FACE_SCORE_THRESHOLD) continue;
                cv::Point2f center(row[3], row[4]);
                cv::Point2f extent(row[5], row[6]);
                cv::Rect box(static_cast<int>((center.x - extent.x / 2.0f) * frame.cols),
                             static_cast<int>((center.y - extent.y / 2.0f) * frame.rows),
                             static_cast<int>(extent.x * frame.cols),
                             static_cast<int>(extent.y * frame.rows));
                if (box.width < 8 || box.height < 8) continue;
                FaceDetection detection;
                detection.box = box & cv::Rect(0, 0, frame.cols, frame.rows);
                detection.score = score;
                if (detection.box.width > 0 && detection.box.height > 0) {
                    found.push_back(detection);
                }
            }
        } catch (const cv::Exception &error) {
            fprintf(stderr, "[VisionEngine] Face detection failed: %s\n", error.what());
        }
        return found;
    }

private:
    cv::dnn::Net net_;
    bool         loaded_ = false;
};

/* Haar cascade face detector. Reports presence, not a probability. */
class CascadeFaceDetector : public FaceDetector {
public:
    bool load(const std::string &path) {
        cascade_ = cv::CascadeClassifier();
        if (!cascade_.load(path)) return false;
        loaded_ = true;
        return true;
    }
    const char *scorer() const override { return "opencv-haarcascade-frontalface"; }
    bool produces_confidence() const override { return false; }
    std::vector<FaceDetection> detect(const cv::Mat &frame) override {
        std::vector<FaceDetection> found;
        if (!loaded_) return found;
        try {
            std::vector<cv::Rect> boxes;
            cascade_.detectMultiScale(frame, boxes, 1.1, 5, 0,
                                      cv::Size(std::max(20, frame.cols / 10),
                                               std::max(20, frame.rows / 10)));
            for (const cv::Rect &box : boxes) {
                FaceDetection detection;
                detection.box = box;
                detection.score = 0.0f;   /* a cascade yields no probability */
                found.push_back(detection);
            }
        } catch (const cv::Exception &error) {
            fprintf(stderr, "[VisionEngine] Cascade detection failed: %s\n", error.what());
        }
        return found;
    }

private:
    cv::CascadeClassifier cascade_;
    bool                   loaded_ = false;
};

struct ObjectDetection {
    int         class_id;
    cv::Rect    box;
    float       score;
};

/* Object detector for the COCO "cell phone" and "book" classes.
 *
 * The provisioned model is YOLOX-S exported to ONNX (Apache-2.0, OpenCV Zoo).
 * The graph is loaded with OpenCV's DNN module, which keeps the runtime
 * dependency set unchanged.  A Caffe SSD model is still accepted when the
 * manifest pairs a prototxt with the weights, so an appliance that has not
 * yet rotated to the ONNX model keeps working.
 */
class CocoObjectDetector {
public:
    bool load(const std::string &weights, const std::string &prototxt) {
        try {
            if (!prototxt.empty()) {
                net_ = cv::dnn::readNetFromCaffe(prototxt, weights);
                is_yolo_ = false;
            } else {
                net_ = cv::dnn::readNetFromONNX(weights);
                is_yolo_ = true;
            }
        } catch (const cv::Exception &error) {
            fprintf(stderr, "[VisionEngine] Object detector could not be loaded: %s\n", error.what());
            return false;
        }
        loaded_ = true;
        return true;
    }
    bool available() const { return loaded_; }
    bool is_yolo() const { return is_yolo_; }

    std::vector<ObjectDetection> detect(const cv::Mat &frame) {
        std::vector<ObjectDetection> found;
        if (!loaded_) return found;
        try {
            if (is_yolo_) {
                detect_yolo(frame, found);
            } else {
                detect_ssd(frame, found);
            }
        } catch (const cv::Exception &error) {
            fprintf(stderr, "[VisionEngine] Object detection failed: %s\n", error.what());
        }
        return found;
    }

private:
    /* YOLOX letterboxes the input to a square while preserving aspect
       ratio, anchoring the resized image at the top-left corner.  The same
       transform is inverted for every output box. */
    static void letterbox(const cv::Mat &frame, cv::Mat &out,
                          float &scale, int &pad_x, int &pad_y) {
        const int target = OBJECT_INPUT_SIZE;
        scale = std::min(static_cast<float>(target) / frame.cols,
                         static_cast<float>(target) / frame.rows);
        const int width  = std::max(1, static_cast<int>(std::round(frame.cols * scale)));
        const int height = std::max(1, static_cast<int>(std::round(frame.rows * scale)));
        pad_x = 0;
        pad_y = 0;

        cv::Mat resized;
        cv::resize(frame, resized, cv::Size(width, height));
        out = cv::Mat(target, target, CV_8UC3, cv::Scalar(114, 114, 114));
        resized.copyTo(out(cv::Rect(0, 0, width, height)));
    }

    void detect_yolo(const cv::Mat &frame, std::vector<ObjectDetection> &found) {
        cv::Mat input;
        float scale = 1.0f;
        int pad_x = 0, pad_y = 0;
        letterbox(frame, input, scale, pad_x, pad_y);

        /* YOLOX consumes RGB pixels in the 0..255 range; its normalisation is
           baked into the exported graph. */
        cv::Mat blob = cv::dnn::blobFromImage(input, 1.0,
                                              cv::Size(OBJECT_INPUT_SIZE, OBJECT_INPUT_SIZE),
                                              cv::Scalar(), true, false);
        net_.setInput(blob);
        cv::Mat output = net_.forward();

        /* YOLOX output is [1, anchors, 5 + classes].  The first four values
           are raw cx, cy, width, height offsets, the fifth is objectness and
           the remainder are per-class probabilities. */
        if (output.dims != 3) return;
        const int anchors = output.size[1];
        const int attrs   = output.size[2];
        if (attrs < 6) return;
        const int class_count = attrs - 5;

        std::vector<cv::Rect> boxes;
        std::vector<float> scores;
        std::vector<int> class_ids;
        boxes.reserve(anchors);
        scores.reserve(anchors);
        class_ids.reserve(anchors);

        int anchor_index = 0;
        for (int stride : {8, 16, 32}) {
            const int cells = OBJECT_INPUT_SIZE / stride;
            for (int y = 0; y < cells; ++y) {
                for (int x = 0; x < cells; ++x, ++anchor_index) {
                    if (anchor_index >= anchors) break;
                    const float *row = output.ptr<float>(0, anchor_index);
                    const float objectness = row[4];
                    if (objectness < 0.05f) continue;

                    int best_class = -1;
                    float best_score = 0.0f;
                    for (int c = 0; c < class_count; ++c) {
                        const float score = objectness * row[5 + c];
                        if (score > best_score) {
                            best_score = score;
                            best_class = c;
                        }
                    }
                    if (best_score < OBJECT_SCORE_THRESHOLD) continue;
                    if (best_class != COCO_CELL_PHONE && best_class != COCO_BOOK) continue;

                    const float cx = (row[0] + x) * stride;
                    const float cy = (row[1] + y) * stride;
                    const float w  = std::exp(row[2]) * stride;
                    const float h  = std::exp(row[3]) * stride;

                    cv::Rect box(static_cast<int>((cx - w / 2.0f - pad_x) / scale),
                                 static_cast<int>((cy - h / 2.0f - pad_y) / scale),
                                 static_cast<int>(w / scale),
                                 static_cast<int>(h / scale));
                    box &= cv::Rect(0, 0, frame.cols, frame.rows);
                    if (box.width <= 0 || box.height <= 0) continue;
                    boxes.push_back(box);
                    scores.push_back(best_score);
                    class_ids.push_back(best_class);
                }
            }
        }

        std::vector<int> keep;
        cv::dnn::NMSBoxesBatched(boxes, scores, class_ids,
                                 OBJECT_SCORE_THRESHOLD, OBJECT_NMS_THRESHOLD, keep);
        for (int index : keep) {
            ObjectDetection detection;
            detection.class_id = class_ids[index];
            detection.box = boxes[index];
            detection.score = scores[index];
            found.push_back(detection);
        }
    }

    void detect_ssd(const cv::Mat &frame, std::vector<ObjectDetection> &found) {
        cv::Mat blob = cv::dnn::blobFromImage(frame, 0.007843,
                                              cv::Size(300, 300),
                                              cv::Scalar(127.5, 127.5, 127.5));
        net_.setInput(blob);
        cv::Mat detections = net_.forward();
        std::vector<ObjectDetection> candidates;
        for (int i = 0; i < detections.size[2]; ++i) {
            const float *row = detections.ptr<float>(0) + detections.step[2] * i;
            int class_id = static_cast<int>(row[0]);
            float score = row[1];
            if (score < OBJECT_SCORE_THRESHOLD) continue;
            if (class_id != COCO_CELL_PHONE && class_id != COCO_BOOK) continue;
            cv::Point2f center(row[3], row[4]);
            cv::Point2f extent(row[5], row[6]);
            ObjectDetection detection;
            detection.class_id = class_id;
            detection.score = score;
            detection.box = cv::Rect(static_cast<int>((center.x - extent.x / 2.0f) * frame.cols),
                                     static_cast<int>((center.y - extent.y / 2.0f) * frame.rows),
                                     static_cast<int>(extent.x * frame.cols),
                                     static_cast<int>(extent.y * frame.rows)) &
                            cv::Rect(0, 0, frame.cols, frame.rows);
            if (detection.box.width > 0 && detection.box.height > 0) {
                candidates.push_back(detection);
            }
        }
        apply_nms(candidates, found);
    }

    static void apply_nms(const std::vector<ObjectDetection> &candidates,
                          std::vector<ObjectDetection> &out) {
        for (int cls : {COCO_CELL_PHONE, COCO_BOOK}) {
            std::vector<cv::Rect> boxes;
            std::vector<float> scores;
            for (const auto &candidate : candidates) {
                if (candidate.class_id != cls) continue;
                boxes.push_back(candidate.box);
                scores.push_back(candidate.score);
            }
            std::vector<int> keep;
            cv::dnn::NMSBoxes(boxes, scores, OBJECT_SCORE_THRESHOLD,
                              OBJECT_NMS_THRESHOLD, keep);
            for (int index : keep) {
                ObjectDetection detection;
                detection.class_id = cls;
                detection.box = boxes[index];
                detection.score = scores[index];
                out.push_back(detection);
            }
        }
    }

    cv::dnn::Net net_;
    bool         loaded_ = false;
    bool         is_yolo_ = true;
};

/* LBF facial landmark model, used for head pose. */
class LandmarkDetector {
public:
    bool load(const std::string &path) {
        try {
            facemark_ = cv::face::FacemarkLBF::create();
            facemark_->loadModel(cv::String(path));
        } catch (const cv::Exception &error) {
            fprintf(stderr, "[VisionEngine] Landmark model could not be loaded: %s\n", error.what());
            return false;
        }
        loaded_ = true;
        return true;
    }
    bool available() const { return loaded_; }
    std::vector<cv::Point2f> landmarks(const cv::Mat &gray, const cv::Rect &face) {
        std::vector<cv::Point2f> points;
        if (!loaded_) return points;
        try {
            std::vector<cv::Rect> faces;
            faces.push_back(face);
            std::vector<std::vector<cv::Point2f> > found;
            if (!facemark_->fit(gray, faces, found) || found.empty()) {
                return std::vector<cv::Point2f>();
            }
            points = found[0];
        } catch (const cv::Exception &error) {
            fprintf(stderr, "[VisionEngine] Landmark detection failed: %s\n", error.what());
            return std::vector<cv::Point2f>();
        }
        return points;
    }

private:
    cv::Ptr<cv::face::Facemark> facemark_;
    bool                        loaded_ = false;
};

FaceDetector     *g_face_detector = nullptr;
SsdFaceDetector  g_ssd_face;
CascadeFaceDetector g_cascade_face;
CocoObjectDetector   g_object_detector;
LandmarkDetector g_landmarks;
std::string      g_scorer;

} // namespace

int vision_engine_init(const char *config_path) {
    if (g_face_detector) {
        delete g_face_detector;
        g_face_detector = nullptr;
    }
    g_scorer.clear();

    std::map<std::string, ModelArtifact> artifacts;
    if (!load_manifest(config_path, artifacts)) {
        fprintf(stderr,
                "[VisionEngine] FATAL: no usable model manifest was supplied "
                "(EXAMOS_PROCTOR_DETECTOR_CONFIG). A detector artefact must be provisioned explicitly.\n");
        return VISION_ENGINE_NO_DETECTOR;
    }

    /* Verify every artefact that is present.
     *
     * Required artefacts (the Haar cascade face detector) are fatal when
     * missing or corrupted — the engine cannot operate without a face
     * detector.  Optional artefacts (Caffe SSD face DNN, YOLOv8 object
     * DNN, LBF landmark model) produce a warning and are skipped; the
     * engine falls back gracefully:
     *   - Caffe SSD missing  → use Haar cascade only
     *   - YOLOv8 missing     → object detection unavailable
     *   - LBF missing        → head pose estimation unavailable
     */
    for (auto &entry : artifacts) {
        entry.second.verified = verify_artifact(entry.second);
        if (!entry.second.verified) {
            /* Determine whether this artefact is required (face-cascade) or
               optional (DNN weights / landmarks). */
            bool required = (entry.first == ROLE_FACE_CASCADE);
            if (required) {
                fprintf(stderr,
                        "[VisionEngine] FATAL: required detector artefact for role '%s' was "
                        "rejected — cannot continue without a face detector.\n",
                        entry.first.c_str());
                return VISION_ENGINE_NO_DETECTOR;
            } else {
                fprintf(stderr,
                        "[VisionEngine] WARNING: optional detector artefact for role '%s' "
                        "is missing or could not be verified — that capability will be "
                        "unavailable.\n",
                        entry.first.c_str());
                /* Remove from the map so the loader below does not attempt to
                   use an unverified path. */
                entry.second.path.clear();
            }
        }
    }

    /* The face detector is preferred when a Caffe SSD DNN is provisioned and
       verified.  If those weights are absent or failed verification the engine
       falls back transparently to the bundled Haar cascade. */
    auto face_proto   = artifacts.find(ROLE_FACE_DNN_PROTOTXT);
    auto face_weights = artifacts.find(ROLE_FACE_DNN_WEIGHTS);
    if (face_proto   != artifacts.end() && !face_proto->second.path.empty() &&
        face_weights != artifacts.end() && !face_weights->second.path.empty()) {
        if (g_ssd_face.load(face_proto->second.path, face_weights->second.path)) {
            g_face_detector = &g_ssd_face;
            g_scorer = g_ssd_face.scorer();
        } else {
            fprintf(stderr,
                    "[VisionEngine] WARNING: Caffe SSD face detector failed to load — "
                    "falling back to Haar cascade.\n");
        }
    }
    if (!g_face_detector) {
        auto cascade = artifacts.find(ROLE_FACE_CASCADE);
        if (cascade != artifacts.end() && !cascade->second.path.empty() &&
            g_cascade_face.load(cascade->second.path)) {
            g_face_detector = &g_cascade_face;
            g_scorer = g_cascade_face.scorer();
        } else {
            fprintf(stderr,
                    "[VisionEngine] WARNING: Haar cascade face detector could not be "
                    "loaded — the cascade file may be missing.\n");
        }
    }
    if (!g_face_detector) {
        fprintf(stderr, "[VisionEngine] FATAL: the manifest names no usable face detector.\n");
        return VISION_ENGINE_NO_DETECTOR;
    }

    /* The object detector (YOLOv8n ONNX) is optional.  When its weights are
       absent or failed verification a warning is emitted and object detection
       is simply disabled - phone/book events report that no approved detector
       is provisioned. */
    auto object_weights = artifacts.find(ROLE_OBJECT_DNN_WEIGHTS);
    auto object_proto   = artifacts.find(ROLE_OBJECT_DNN_PROTOTXT);
    if (object_weights != artifacts.end() && !object_weights->second.path.empty()) {
        std::string prototxt;
        if (object_proto != artifacts.end() && !object_proto->second.path.empty() &&
            object_weights->second.framework != "onnx") {
            prototxt = object_proto->second.path;
        }
        if (!g_object_detector.load(object_weights->second.path, prototxt)) {
            fprintf(stderr,
                    "[VisionEngine] WARNING: object detector failed to load - "
                    "phone and book detection will be unavailable.\n");
        }
    } else {
        fprintf(stderr,
                "[VisionEngine] WARNING: object detector weights are not provisioned - "
                "object detection (phone, book) will be unavailable.\n");
    }

    /* The LBF landmark model is optional.  Without it head pose estimation is
       disabled; a "UNAVAILABLE" payload is emitted for HEAD_POSE events. */
    auto landmark = artifacts.find(ROLE_LANDMARKS);
    if (landmark != artifacts.end() && !landmark->second.path.empty()) {
        if (!g_landmarks.load(landmark->second.path)) {
            fprintf(stderr,
                    "[VisionEngine] WARNING: LBF landmark model failed to load — "
                    "head pose estimation will be unavailable.\n");
        }
    } else {
        fprintf(stderr,
                "[VisionEngine] WARNING: LBF landmark model file is not provisioned — "
                "head pose estimation will be unavailable.\n");
    }

    fprintf(stderr, "[VisionEngine] Face detector ready: %s (objects=%s, landmarks=%s)\n",
            g_scorer.c_str(),
            g_object_detector.available() ? "on" : "off",
            g_landmarks.available() ? "on" : "off");
    return VISION_ENGINE_OK;
}

void vision_engine_destroy(void) {
    /* The active detector is one of two file-scope singletons; it is not
       heap-allocated and must not be deleted. */
    g_face_detector = nullptr;
    g_scorer.clear();
}

const char *vision_engine_scorer(void) {
    return g_scorer.empty() ? NULL : g_scorer.c_str();
}

namespace {

/* Normalises a pixel box to the frame's coordinate space. */
vision_bbox_t normalise_box(const cv::Rect &box, int width, int height, float score) {
    vision_bbox_t bbox;
    bbox.x = static_cast<float>(box.x) / static_cast<float>(width);
    bbox.y = static_cast<float>(box.y) / static_cast<float>(height);
    bbox.width = static_cast<float>(box.width) / static_cast<float>(width);
    bbox.height = static_cast<float>(box.height) / static_cast<float>(height);
    bbox.confidence = score;
    return bbox;
}

/*
 * Estimates head pose from the 68-point landmark set.
 *
 * The pose is recovered with a perspective-n-point solve against a generic
 * face model, and the quality of the solution is reported as the
 * reprojection error in pixels. The reported confidence is a documented,
 * deterministic function of that error, and the payload states the basis.
 */
bool estimate_head_pose(const std::vector<cv::Point2f> &points,
                        int width, int height,
                        float &yaw, float &pitch, float &roll, float &confidence) {
    if (points.size() < 68) return false;

    /* Chin, eye corners, mouth corners and nose tip. */
    static const int indices[6] = { 8, 36, 45, 48, 54, 30 };

    cv::Point3f model_points[6] = {
        cv::Point3f(0.0f,    330.0f,   0.0f),   /* chin        */
        cv::Point3f(225.0f,  330.0f, -105.0f),   /* left eye    */
        cv::Point3f(-225.0f, 330.0f, -105.0f),   /* right eye   */
        cv::Point3f(150.0f, -150.0f, -125.0f),   /* left mouth  */
        cv::Point3f(-150.0f,-150.0f, -125.0f),   /* right mouth */
        cv::Point3f(0.0f,    0.0f,     0.0f)     /* nose tip    */
    };

    std::vector<cv::Point3f> object_points;
    std::vector<cv::Point2f> image_points;
    for (int i = 0; i < 6; ++i) {
        object_points.push_back(model_points[i]);
        image_points.push_back(points[indices[i]]);
    }

    double rotation[9], translation[3];
    bool solved = false;
    try {
        cv::Mat rotation_matrix(3, 3, CV_64F, rotation);
        cv::Mat translation_vector(3, 1, CV_64F, translation);
        solved = cv::solvePnP(object_points, image_points,
                              cv::Mat::eye(3, 3, CV_64F), cv::Mat(),
                              rotation_matrix,
                              translation_vector,
                              false, cv::SOLVEPNP_ITERATIVE);
    } catch (const cv::Exception &) {
        solved = false;
    }
    if (!solved) return false;

    /* The reprojection error is the quality of the solution. */
    std::vector<cv::Point2f> projected;
    try {
        cv::Mat rotation_matrix(3, 3, CV_64F, rotation);
        cv::Mat translation_vector(3, 1, CV_64F, translation);
        cv::projectPoints(object_points, rotation_matrix,
                          translation_vector,
                          cv::Mat::eye(3, 3, CV_64F), cv::Mat(), projected);
    } catch (const cv::Exception &) {
        return false;
    }

    double sum = 0.0;
    for (size_t i = 0; i < image_points.size(); ++i) {
        double dx = projected[i].x - image_points[i].x;
        double dy = projected[i].y - image_points[i].y;
        sum += dx * dx + dy * dy;
    }
    double rms = std::sqrt(sum / static_cast<double>(image_points.size()));

    /* The confidence is 1 - RMS/10 pixels, clamped to [0,1]. */
    confidence = static_cast<float>(1.0 - rms / 10.0);
    if (confidence < 0.0f) confidence = 0.0f;
    if (confidence > 1.0f) confidence = 1.0f;

    cv::Mat rotation_matrix(3, 3, CV_64F, rotation);
    cv::Mat rotation_vector;
    cv::Rodrigues(rotation_matrix, rotation_vector);
    double ry = rotation_vector.at<double>(0) * 180.0 / CV_PI;
    double rx = rotation_vector.at<double>(1) * 180.0 / CV_PI;
    double rz = rotation_vector.at<double>(2) * 180.0 / CV_PI;

    yaw = static_cast<float>(ry);
    pitch = static_cast<float>(rx);
    roll = static_cast<float>(rz);
    (void)width;
    (void)height;
    return true;
}

} // namespace

int vision_engine_analyze_frame(const uint8_t *pixel_data, int width, int height,
                                int stride, int channels, uint64_t frame_seq,
                                vision_frame_result_t *out_result) {
    if (!out_result) return VISION_ENGINE_NO_FRAME;

    memset(out_result, 0, sizeof(vision_frame_result_t));
    out_result->frame_sequence = frame_seq;
    out_result->timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (!g_face_detector) {
        out_result->analysis_status = VISION_ENGINE_NO_DETECTOR;
        snprintf(out_result->scorer, sizeof(out_result->scorer), "none");
        return VISION_ENGINE_NO_DETECTOR;
    }
    if (!pixel_data || width <= 0 || height <= 0 || stride <= 0 ||
        (channels != 1 && channels != 3)) {
        out_result->analysis_status = VISION_ENGINE_NO_FRAME;
        snprintf(out_result->scorer, sizeof(out_result->scorer), "%s", g_scorer.c_str());
        return VISION_ENGINE_NO_FRAME;
    }

    snprintf(out_result->scorer, sizeof(out_result->scorer), "%s", g_scorer.c_str());
    out_result->confidence_available = g_face_detector->produces_confidence() ? 1 : 0;

    cv::Mat frame(height, width, channels == 1 ? CV_8UC1 : CV_8UC3,
                  const_cast<uint8_t *>(pixel_data), stride);
    cv::Mat gray;
    if (channels == 3) {
        cv::cvtColor(frame, gray, cv::COLOR_BGR2GRAY);
    } else {
        gray = frame;
    }
    cv::equalizeHist(gray, gray);

    std::vector<FaceDetection> faces = g_face_detector->detect(frame);

    out_result->face_count = 0;
    for (const FaceDetection &face : faces) {
        if (out_result->face_count >= 8) break;
        out_result->faces[out_result->face_count++] =
            normalise_box(face.box, width, height, face.score);
    }

    /* Head pose, when a landmark model is provisioned and a face was found. */
    out_result->head_pose_confidence = 0.0f;
    if (g_landmarks.available() && out_result->face_count > 0) {
        const cv::Rect face_box = faces[0].box;
        std::vector<cv::Point2f> points = g_landmarks.landmarks(gray, face_box);
        float yaw = 0.0f, pitch = 0.0f, roll = 0.0f, confidence = 0.0f;
        if (estimate_head_pose(points, width, height, yaw, pitch, roll, confidence)) {
            out_result->yaw_deg = yaw;
            out_result->pitch_deg = pitch;
            out_result->roll_deg = roll;
            out_result->head_pose_confidence = confidence;
        }
    }

    /* Objects: a phone or a book in the examination frame. */
    out_result->phone_detected = 0;
    out_result->book_detected = 0;
    {
        std::vector<ObjectDetection> objects = g_object_detector.detect(frame);
        for (const ObjectDetection &object : objects) {
            if (object.class_id == COCO_CELL_PHONE && !out_result->phone_detected) {
                out_result->phone_detected = 1;
                out_result->phone_confidence = object.score;
                out_result->phone_bbox = normalise_box(object.box, width, height, object.score);
            } else if (object.class_id == COCO_BOOK && !out_result->book_detected) {
                out_result->book_detected = 1;
                out_result->book_confidence = object.score;
                out_result->book_bbox = normalise_box(object.box, width, height, object.score);
            }
        }
    }

    out_result->analysis_status = VISION_ENGINE_OK;
    return VISION_ENGINE_OK;
}

int vision_engine_format_event_json(const vision_frame_result_t *res, const char *event_type,
                                     char *out_json, size_t max_out) {
    if (!res || !event_type || !out_json || max_out == 0) return -1;

    if (res->analysis_status != VISION_ENGINE_OK) {
        snprintf(out_json, max_out,
                 "{\"status\":\"UNAVAILABLE\",\"reason\":\"%s\",\"scorer\":\"%s\"}",
                 res->analysis_status == VISION_ENGINE_NO_DETECTOR
                     ? "no approved detector is available"
                     : "the supplied frame could not be analysed",
                 res->scorer[0] ? res->scorer : "none");
        return 0;
    }

    if (strcmp(event_type, "FACE_PRESENT") == 0 ||
        strcmp(event_type, "MULTIPLE_FACES") == 0 ||
        strcmp(event_type, "NO_FACE") == 0) {
        size_t used = 0;
        int written = snprintf(out_json, max_out,
                     "{\"faceCount\":%d,\"scorer\":\"%s\",\"faces\":[",
                     res->face_count, res->scorer[0] ? res->scorer : "none");
        if (written < 0) return -1;
        used = static_cast<size_t>(written);
        for (int i = 0; i < res->face_count && used + 1 < max_out; i++) {
            const vision_bbox_t &bbox = res->faces[i];
            /* A confidence field is present only when the scorer produced
               one. Omitting it is honest; reporting zero would read as
               "no confidence" rather than "not a probabilistic score". */
            if (res->confidence_available) {
                written = snprintf(out_json + used, max_out - used,
                         "%s{\"confidence\":%.4f,\"bbox\":{\"x\":%.4f,\"y\":%.4f,\"width\":%.4f,\"height\":%.4f}}",
                         i > 0 ? "," : "",
                         bbox.confidence, bbox.x, bbox.y, bbox.width, bbox.height);
            } else {
                written = snprintf(out_json + used, max_out - used,
                         "%s{\"bbox\":{\"x\":%.4f,\"y\":%.4f,\"width\":%.4f,\"height\":%.4f}}",
                         i > 0 ? "," : "",
                         bbox.x, bbox.y, bbox.width, bbox.height);
            }
            if (written < 0) break;
            used += static_cast<size_t>(written);
        }
        if (used + 3 < max_out) {
            memcpy(out_json + used, "]}\0", 4);
        } else {
            out_json[max_out - 1] = '\0';
        }
    } else if (strcmp(event_type, "HEAD_POSE") == 0) {
        if (res->head_pose_confidence <= 0.0f) {
            snprintf(out_json, max_out,
                     "{\"status\":\"UNAVAILABLE\","
                     "\"reason\":\"head pose requires an approved facial landmark model\"}");
        } else {
            snprintf(out_json, max_out,
                     "{\"yaw\":%.1f,\"pitch\":%.1f,\"roll\":%.1f,"
                     "\"confidence\":%.4f,"
                     "\"confidence_basis\":\"1 - reprojection_error_px/10\"}",
                     res->yaw_deg, res->pitch_deg, res->roll_deg,
                     res->head_pose_confidence);
        }
    } else if (strcmp(event_type, "PHONE_DETECTED") == 0) {
        if (!res->phone_detected) {
            snprintf(out_json, max_out,
                     "{\"detected\":false,"
                     "\"reason\":\"no approved object detector is provisioned for this class\"}");
        } else {
            snprintf(out_json, max_out,
                     "{\"detected\":true,\"confidence\":%.4f,"
                     "\"bbox\":{\"x\":%.4f,\"y\":%.4f,\"width\":%.4f,\"height\":%.4f}}",
                     res->phone_confidence, res->phone_bbox.x, res->phone_bbox.y,
                     res->phone_bbox.width, res->phone_bbox.height);
        }
    } else if (strcmp(event_type, "BOOK_DETECTED") == 0) {
        if (!res->book_detected) {
            snprintf(out_json, max_out,
                     "{\"detected\":false,"
                     "\"reason\":\"no approved object detector is provisioned for this class\"}");
        } else {
            snprintf(out_json, max_out,
                     "{\"detected\":true,\"confidence\":%.4f,"
                     "\"bbox\":{\"x\":%.4f,\"y\":%.4f,\"width\":%.4f,\"height\":%.4f}}",
                     res->book_confidence, res->book_bbox.x, res->book_bbox.y,
                     res->book_bbox.width, res->book_bbox.height);
        }
    } else {
        snprintf(out_json, max_out, "{\"status\":\"OK\",\"frameSequence\":%lu}",
                 (unsigned long)res->frame_sequence);
    }

    return 0;
}
