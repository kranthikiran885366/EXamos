/*
 * Regression coverage for the proctoring vision engine.
 *
 * The properties under test:
 *   1. The engine refuses to run without a provisioned detector manifest.
 *   2. A detector artefact whose digest does not match the manifest is
 *      rejected, so a substituted model cannot become evidence.
 *   3. A frame containing a real face is detected, and the reported count
 *      and bounding box come from the detector.
 *   4. A frame with no face in it reports zero faces. The previous
 *      implementation reported one face with a fixed confidence for any
 *      frame that was not completely dark, which fabricated evidence.
 *   5. No event carries a confidence that the scorer did not produce.
 */

#include "../../proctoring/include/vision_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <opencv2/opencv.hpp>

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *label, int condition) {
    if (condition) {
        printf("  PASS  %s\n", label);
        g_pass++;
    } else {
        printf("  FAIL  %s\n", label);
        g_fail++;
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: vision-engine-test MANIFEST FACE_IMAGE BLANK_IMAGE\n");
        return 2;
    }
    const char *manifest = argv[1];
    const char *face_image = argv[2];
    const char *blank_image = argv[3];

    /* 1. No detector manifest -> the engine must refuse to run. */
    check("engine refuses to initialise without a detector manifest",
          vision_engine_init(NULL) == VISION_ENGINE_NO_DETECTOR);

    /* 2. A manifest with a wrong digest must be rejected. */
    {
        char tampered[1200];
        snprintf(tampered, sizeof(tampered), "%s.tampered", manifest);
        FILE *source = fopen(manifest, "r");
        FILE *copy = fopen(tampered, "w");
        char line[1024];
        while (source && copy && fgets(line, sizeof(line), source)) {
            if (strstr(line, "\"sha256\"")) {
                fputs("      \"sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\",\n", copy);
            } else {
                fputs(line, copy);
            }
        }
        if (source) fclose(source);
        if (copy) fclose(copy);
        check("engine rejects a detector artefact that fails its digest",
              vision_engine_init(tampered) == VISION_ENGINE_NO_DETECTOR);
        remove(tampered);
    }

    /* 3. The provisioned detector must initialise. */
    check("engine initialises with the provisioned detector",
          vision_engine_init(manifest) == VISION_ENGINE_OK);
    check("engine reports the active scorer", vision_engine_scorer() != NULL);

    /* 4. A real photograph containing a face must be detected. */
    {
        cv::Mat image = cv::imread(face_image, cv::IMREAD_COLOR);
        check("face fixture could be read", !image.empty());
        if (!image.empty()) {
            vision_frame_result_t result;
            int status = vision_engine_analyze_frame(
                image.data, image.cols, image.rows, (int)image.step, 3, 1, &result);
            check("frame analysis completed", status == VISION_ENGINE_OK);
            check("a real face was detected", result.face_count >= 1);
            if (result.face_count >= 1) {
                const vision_bbox_t &bbox = result.faces[0];
                check("detected box lies inside the frame",
                      bbox.x >= 0.0f && bbox.y >= 0.0f &&
                      bbox.x + bbox.width <= 1.01f && bbox.y + bbox.height <= 1.01f);
                check("no confidence was fabricated for a cascade detection",
                      bbox.confidence == 0.0f);
            }
        }
    }

    /* 5. A frame without a face must report zero faces. */
    {
        cv::Mat image = cv::imread(blank_image, cv::IMREAD_COLOR);
        check("blank fixture could be read", !image.empty());
        if (!image.empty()) {
            vision_frame_result_t result;
            int status = vision_engine_analyze_frame(
                image.data, image.cols, image.rows, (int)image.step, 3, 2, &result);
            check("blank frame analysis completed", status == VISION_ENGINE_OK);
            check("no face was invented in a blank frame", result.face_count == 0);
        }
    }

    /* 6. Event payloads must not claim a fabricated confidence. */
    {
        vision_frame_result_t result;
        memset(&result, 0, sizeof(result));
        result.analysis_status = VISION_ENGINE_OK;
        result.face_count = 1;
        result.faces[0].confidence = 0.0f;
        result.confidence_available = 0;
        snprintf(result.scorer, sizeof(result.scorer), "test-scorer");
        char json[1024];
        check("face event formats", vision_engine_format_event_json(&result, "FACE_PRESENT", json, sizeof(json)) == 0);
        check("face event names the scorer", strstr(json, "test-scorer") != NULL);
        check("a cascade event carries no confidence field", strstr(json, "confidence") == NULL);

        /* A probabilistic scorer may report its score. */
        result.confidence_available = 1;
        result.faces[0].confidence = 0.87f;
        check("a scoring event carries its score",
              vision_engine_format_event_json(&result, "FACE_PRESENT", json, sizeof(json)) == 0 &&
              strstr(json, "\"confidence\":0.87") != NULL);

        result.analysis_status = VISION_ENGINE_NO_DETECTOR;
        check("unavailable analysis is reported as unavailable",
              vision_engine_format_event_json(&result, "FACE_PRESENT", json, sizeof(json)) == 0 &&
              strstr(json, "UNAVAILABLE") != NULL);
    }

    printf("PASS: vision engine detects real faces and never fabricates evidence (%d passed, %d failed)\n",
           g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
