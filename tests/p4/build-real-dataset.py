#!/usr/bin/env python3
"""
Build a real labelled detection dataset from COCO val2017.

Every clip is a three-second video derived from a real COCO photograph.  The
ground-truth label comes from the COCO annotations, not from a detector:

  single_face    exactly one frontal face (person keypoints visible)
  multiple_faces two or more frontal faces
  no_face        a photograph containing no annotated person
  phone_present  a photograph containing a COCO "cell phone" instance
  book_present   a photograph containing a COCO "book" instance

The script never invents a label.  A candidate is accepted only when the
annotation needed for that label exists and the resulting crop keeps the
relevant object at a size the detector can plausibly resolve; the crop and
face/object boxes are recorded in each clip's JSON so the evaluation can be
audited.

This is a development evaluation dataset.  The source photographs are not
redistributed: only the download script and digests are committed.
"""

import argparse
import datetime
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import zipfile

FRONTAL_KEYPOINTS = (0, 1, 2)  # nose, left eye, right eye
COCO_CELL_PHONE = 77
COCO_BOOK = 84
OUT_W, OUT_H = 640, 480
CLIP_SECONDS = 3
CLIP_FPS = 5


def fail(message):
    print(f"[dataset] FATAL: {message}", file=sys.stderr)
    sys.exit(1)


def load_annotations(cache):
    ann_zip = os.path.join(cache, "annotations_trainval2017.zip")
    if not os.path.isfile(ann_zip):
        fail(f"annotations archive not found at {ann_zip}")

    targets = {
        "instances": "annotations/instances_val2017.json",
        "keypoints": "annotations/person_keypoints_val2017.json",
    }
    paths = {}
    with zipfile.ZipFile(ann_zip) as archive:
        for name, member in targets.items():
            path = os.path.join(cache, member)
            if not os.path.isfile(path):
                archive.extract(member, cache)
            paths[name] = path

    with open(paths["instances"], encoding="utf-8") as handle:
        instances = json.load(handle)
    with open(paths["keypoints"], encoding="utf-8") as handle:
        keypoints = json.load(handle)
    return instances, keypoints


def face_box_from_keypoints(keypoints, require_ears=False):
    """Return an estimated face box, or None for a non-frontal face."""
    points = []
    for index in range(5):
        x, y, visibility = keypoints[index * 3:index * 3 + 3]
        if visibility > 0:
            points.append((float(x), float(y)))
    if len(points) < 3:
        return None
    # Require a visible nose and both eyes: profile/rear faces are not a fair
    # test of a frontal-face detector.  Multiple-face clips additionally
    # require both ears, which rejects faces turned away or heavily occluded.
    required = (0, 1, 2, 3, 4) if require_ears else FRONTAL_KEYPOINTS
    for index in required:
        threshold = 2 if index in FRONTAL_KEYPOINTS else 1
        if keypoints[index * 3 + 2] < threshold:
            return None

    xs = [point[0] for point in points]
    ys = [point[1] for point in points]
    width = max(xs) - min(xs)
    height = max(ys) - min(ys)
    if width < 6 or height < 3:
        return None
    # The five landmarks cover the eyes, nose and ears.  Expand to a whole
    # face: a little to each side, more above (forehead) and below (chin).
    x0 = min(xs) - 0.20 * width
    x1 = max(xs) + 0.20 * width
    y0 = min(ys) - 0.90 * height
    y1 = max(ys) + 1.15 * height
    return [x0, y0, x1 - x0, y1 - y0]


def clamp_box(box, image_w, image_h):
    x, y, w, h = box
    x0 = max(0.0, min(float(x), image_w - 1.0))
    y0 = max(0.0, min(float(y), image_h - 1.0))
    x1 = max(x0 + 1.0, min(float(x + w), image_w))
    y1 = max(y0 + 1.0, min(float(y + h), image_h))
    return [x0, y0, x1 - x0, y1 - y0]


def fit_aspect(box, image_w, image_h, aspect=OUT_W / OUT_H):
    """Expand a box to the output aspect ratio without losing its contents."""
    x, y, w, h = box
    cx, cy = x + w / 2.0, y + h / 2.0
    if w / h < aspect:
        w = h * aspect
    else:
        h = w / aspect
    x = cx - w / 2.0
    y = cy - h / 2.0

    # Keep the crop inside the image, shifting rather than shrinking.
    if w > image_w:
        w = image_w
        x = 0.0
    if h > image_h:
        h = image_h
        y = 0.0
    x = min(max(0.0, x), image_w - w)
    y = min(max(0.0, y), image_h - h)
    return [int(round(x)), int(round(y)), int(round(w)), int(round(h))]


def expand_box(box, factor_x, factor_y=None):
    if factor_y is None:
        factor_y = factor_x
    x, y, w, h = box
    cx, cy = x + w / 2.0, y + h / 2.0
    w *= factor_x
    h *= factor_y
    return [cx - w / 2.0, cy - h / 2.0, w, h]


def union(boxes):
    x0 = min(box[0] for box in boxes)
    y0 = min(box[1] for box in boxes)
    x1 = max(box[0] + box[2] for box in boxes)
    y1 = max(box[1] + box[3] for box in boxes)
    return [x0, y0, x1 - x0, y1 - y0]


def box_inside(inner, outer, tolerance=2.0):
    return (inner[0] >= outer[0] - tolerance and
            inner[1] >= outer[1] - tolerance and
            inner[0] + inner[2] <= outer[0] + outer[2] + tolerance and
            inner[1] + inner[3] <= outer[1] + outer[3] + tolerance)


def scaled_size(box, crop):
    """Size of a box after the crop is resized to the output resolution."""
    return (box[2] * OUT_W / crop[2], box[3] * OUT_H / crop[3])


def face_candidates(keypoints, images, require_ears=False, min_source=40):
    """Return per-image lists of plausible frontal-face boxes."""
    by_image = {}
    for annotation in keypoints["annotations"]:
        if annotation.get("iscrowd"):
            continue
        box = face_box_from_keypoints(annotation["keypoints"], require_ears)
        if box is None:
            continue
        image = images.get(annotation["image_id"])
        if image is None:
            continue
        box = clamp_box(box, image["width"], image["height"])
        # Judge resolution in source pixels.  Upscaling a 30-pixel face to the
        # output size does not create detail the detector can use.
        if box[2] < min_source or box[3] < min_source:
            continue
        by_image.setdefault(annotation["image_id"], []).append(box)
    return by_image


def make_single_face_candidates(faces, images):
    candidates = []
    for image_id, boxes in faces.items():
        if len(boxes) != 1:
            continue
        image = images[image_id]
        face = boxes[0]
        # Keep the face prominent: about one third of the frame width.
        crop = fit_aspect(expand_box(face, 2.8), image["width"], image["height"])
        if not box_inside(face, crop):
            continue
        if scaled_size(face, crop)[0] < 45:
            continue
        candidates.append((image_id, crop, {"face_count": 1, "faces": [face]}))
    return candidates


def make_multiple_face_candidates(faces, images):
    candidates = []
    for image_id, boxes in faces.items():
        if len(boxes) < 2:
            continue
        # Evaluate every pair and keep the most compact, usable pairing.
        best = None
        for first in range(len(boxes)):
            for second in range(first + 1, len(boxes)):
                pair = [boxes[first], boxes[second]]
                combined = union(pair)
                image = images[image_id]
                crop = fit_aspect(expand_box(combined, 1.15), image["width"], image["height"])
                if not all(box_inside(face, crop) for face in pair):
                    continue
                # Both faces must survive the downscale at a size the face
                # detector can resolve; otherwise the clip measures the crop,
                # not the detector.
                if min(scaled_size(face, crop)[0] for face in pair) < 75:
                    continue
                area = crop[2] * crop[3]
                if best is None or area < best[0]:
                    best = (area, crop, pair)
        if best is not None:
            _, crop, pair = best
            candidates.append((image_id, crop,
                               {"face_count": len(pair), "faces": pair}))
    return candidates


def make_no_face_candidates(instances, images, person_ids):
    candidates = []
    for image in instances["images"]:
        image_id = image["id"]
        if image_id in person_ids:
            continue
        width, height = image["width"], image["height"]
        crop_w = min(width, OUT_W * 1.0)
        crop_h = min(height, OUT_H * 1.0)
        if crop_w < 320 or crop_h < 240:
            continue
        crop = fit_aspect([width * 0.1, height * 0.1, crop_w, crop_h], width, height)
        candidates.append((image_id, crop, {"face_count": 0, "faces": []}))
    return candidates


def make_object_candidates(instances, images, category_id, min_source_size, context):
    candidates = []
    categories = {category["id"]: category["name"] for category in instances["categories"]}
    for annotation in instances["annotations"]:
        if annotation["category_id"] != category_id or annotation.get("iscrowd"):
            continue
        image = images.get(annotation["image_id"])
        if image is None:
            continue
        box = clamp_box(annotation["bbox"], image["width"], image["height"])
        if box[2] < min_source_size or box[3] < min_source_size:
            continue
        # Reject objects that are cut off by the image border: the annotator
        # saw only part of the object, and a detector cannot fairly be asked
        # to recognise the remainder.
        if (box[0] <= 1 or box[1] <= 1 or
                box[0] + box[2] >= image["width"] - 1 or
                box[1] + box[3] >= image["height"] - 1):
            continue
        crop = fit_aspect(expand_box(box, context), image["width"], image["height"])
        if not box_inside(box, crop, tolerance=3.0):
            continue
        if min(scaled_size(box, crop)) < 28:
            continue
        candidates.append((annotation["image_id"], crop, {
            "object": categories.get(category_id, "unknown"),
            "object_bbox": box,
            "object_area": box[2] * box[3],
        }))
    return candidates


def choose(candidates, limit, used_images, rng):
    # Prefer candidates whose source image has not already been used, so the
    # clip set covers more scenes.  Within one label, never take two crops
    # from the same photograph.
    fresh = [item for item in candidates if item[0] not in used_images]
    stale = [item for item in candidates if item[0] in used_images]
    rng.shuffle(fresh)
    rng.shuffle(stale)
    chosen = []
    seen = set()
    for item in fresh + stale:
        if item[0] in seen:
            continue
        seen.add(item[0])
        chosen.append(item)
        if len(chosen) >= limit:
            break
    for image_id, _, _ in chosen:
        used_images.add(image_id)
    return chosen


def extract_image(archive, image, cache, destination):
    member = "val2017/" + image["file_name"]
    with zipfile.ZipFile(archive) as val_zip:
        try:
            data = val_zip.read(member)
        except KeyError:
            return False
    with open(destination, "wb") as handle:
        handle.write(data)
    return True


def render_clip(source, crop, destination):
    x, y, w, h = crop
    video_filter = (f"crop={w}:{h}:{x}:{y},scale={OUT_W}:{OUT_H},"
                    f"fps={CLIP_FPS}")
    command = [
        "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
        "-loop", "1", "-i", source,
        "-vf", video_filter,
        "-t", str(CLIP_SECONDS), "-r", str(CLIP_FPS),
        "-frames:v", str(CLIP_SECONDS * CLIP_FPS),
        "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
        "-an", destination,
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        fail(f"ffmpeg failed for {destination}: {result.stderr.strip()}")
    if not os.path.isfile(destination) or os.path.getsize(destination) == 0:
        fail(f"ffmpeg produced no output for {destination}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", required=True, help="COCO archive cache directory")
    parser.add_argument("--out", required=True, help="output dataset directory")
    parser.add_argument("--val-sha", required=True)
    parser.add_argument("--ann-sha", required=True)
    parser.add_argument("--val-url", required=True)
    parser.add_argument("--ann-url", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    val_zip = os.path.join(args.cache, "val2017.zip")
    if not os.path.isfile(val_zip):
        fail(f"val2017 archive not found at {val_zip}")

    instances, keypoints = load_annotations(args.cache)
    images = {image["id"]: image for image in instances["images"]}
    licenses = {license_entry["id"]: license_entry
                for license_entry in instances.get("licenses", [])}

    # Person instances mark photographs that are not "no face" material even
    # when the keypoint annotator skipped the face.
    person_ids = {annotation["image_id"]
                  for annotation in instances["annotations"]
                  if annotation["category_id"] == 1}

    faces = face_candidates(keypoints, images)
    strict_faces = face_candidates(keypoints, images, require_ears=True, min_source=45)
    rng = random.Random(args.seed)
    used_images = set()

    plan = [
        ("single_face", make_single_face_candidates(faces, images), 25, "face"),
        ("multiple_faces", make_multiple_face_candidates(strict_faces, images), 15, "faces"),
        ("no_face", make_no_face_candidates(instances, images, person_ids), 12, "empty"),
        ("phone_present", make_object_candidates(instances, images, COCO_CELL_PHONE,
                                                 40, 2.0), 12, "phone"),
        ("book_present", make_object_candidates(instances, images, COCO_BOOK,
                                                70, 1.6), 12, "book"),
    ]

    if os.path.isdir(args.out):
        for entry in os.listdir(args.out):
            if entry.endswith(".json") or entry.endswith(".mp4"):
                os.remove(os.path.join(args.out, entry))
    else:
        os.makedirs(args.out, exist_ok=True)

    counts = {}
    total = 0
    created_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with tempfile.TemporaryDirectory(prefix="examos-coco-") as workspace:
        for label, candidates, limit, prefix in plan:
            if not candidates:
                print(f"[dataset] WARNING: no candidates for {label}", file=sys.stderr)
                counts[label] = 0
                continue
            chosen = choose(candidates, limit, used_images, rng)
            counts[label] = len(chosen)
            print(f"[dataset] {label}: {len(chosen)} clips from {len(candidates)} candidates")

            for index, (image_id, crop, ground_truth) in enumerate(chosen, start=1):
                image = images[image_id]
                clip_id = f"{prefix}-{index:03d}"
                source_path = os.path.join(workspace, f"{image_id}.jpg")
                if not extract_image(val_zip, image, args.cache, source_path):
                    print(f"[dataset] WARNING: {image['file_name']} missing from archive",
                          file=sys.stderr)
                    continue
                video_path = os.path.join(args.out, f"{clip_id}.mp4")
                render_clip(source_path, crop, video_path)

                license_entry = licenses.get(image.get("license"), {})
                record = {
                    "clip_id": clip_id,
                    "label": label,
                    "duration_sec": CLIP_SECONDS,
                    "resolution": f"{OUT_W}x{OUT_H}",
                    "fps": CLIP_FPS,
                    "annotation_version": "coco-val2017-v1",
                    "source": {
                        "dataset": "COCO val2017",
                        "image_id": image_id,
                        "file_name": image["file_name"],
                        "crop": crop,
                        "image_width": image["width"],
                        "image_height": image["height"],
                        "license_id": image.get("license"),
                        "license_name": license_entry.get("name", "unknown"),
                        "license_url": license_entry.get("url", ""),
                        "image_url": f"http://images.cocodataset.org/val2017/{image['file_name']}",
                    },
                    "ground_truth": ground_truth,
                }
                with open(os.path.join(args.out, f"{clip_id}.json"), "w",
                          encoding="utf-8") as handle:
                    json.dump(record, handle, indent=2, sort_keys=True)
                    handle.write("\n")
                total += 1

    manifest = {
        "schema": "examos-p4-dataset-manifest-v1",
        "dataset": "COCO val2017",
        "synthetic": False,
        "real_photographs": True,
        "description": ("Three-second clips cropped from real COCO val2017 photographs. "
                        "Labels are derived from COCO instance and person-keypoint "
                        "annotations; no detector produced the ground truth."),
        "clips": total,
        "counts": counts,
        "resolution": f"{OUT_W}x{OUT_H}",
        "duration_sec": CLIP_SECONDS,
        "fps": CLIP_FPS,
        "created_utc": created_at,
        "sources": {
            "images": {"url": args.val_url, "sha256": args.val_sha},
            "annotations": {"url": args.ann_url, "sha256": args.ann_sha},
        },
        "annotation_files": {
            "instances": "annotations/instances_val2017.json",
            "person_keypoints": "annotations/person_keypoints_val2017.json",
        },
        "label_method": {
            "single_face": "exactly one person whose nose and both eyes are visible (keypoint visibility 2)",
            "multiple_faces": "two or more such people inside one crop",
            "no_face": "photograph with no person instance annotation",
            "phone_present": "COCO cell phone instance (category 77), non-crowd",
            "book_present": "COCO book instance (category 84), non-crowd",
        },
        "redistribution": ("The source photographs are not redistributed. Only this "
                           "builder, the download script and the archive digests are "
                           "committed; clips are generated locally under a gitignored path."),
    }
    with open(os.path.join(args.out, "DATASET-MANIFEST.json"), "w",
              encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(f"[dataset] wrote {total} clips to {args.out}")
    if total < 50:
        print(f"[dataset] WARNING: only {total} clips were produced; the gate wants at least 50",
              file=sys.stderr)


if __name__ == "__main__":
    main()
