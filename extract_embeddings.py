# =======================================================================
# VGGFace2 Embedding Extraction -- buffalo_l (InsightFace ArcFace ResNet50)
#
# Extracts 512-D L2-normalised ArcFace embeddings for every image in a
# VGGFace2-style directory and saves them to a JSON file with the format:
#
#   { "n000051": [[...512 floats...], [...], ...], "n000052": [...], ... }
#
# Expected dataset layout:
#   DATASET_ROOT/
#     n000051/
#       0001_01.jpg
#       ...
#     n000052/
#       ...
#
# Requirements:  pip install insightface onnxruntime opencv-python
# =======================================================================

import os, json
import numpy as np
import cv2
from insightface.app import FaceAnalysis

# -- Configuration --------------------------------------------------------
DATASET_ROOT = "/path/to/vggface2/train"   # <-- set this
OUTPUT_PATH  = "data_train_resnet50.json"
DET_SIZE     = (640, 640)                  # detection input resolution

# -- Load buffalo_l (ArcFace ResNet50, 512-D) -----------------------------
app = FaceAnalysis(
    name='buffalo_l',
    providers=['CUDAExecutionProvider', 'CPUExecutionProvider']
)
app.prepare(ctx_id=0, det_size=DET_SIZE)

# -- Extract embeddings ---------------------------------------------------
facial_data = {}
person_dirs = sorted([
    d for d in os.listdir(DATASET_ROOT)
    if os.path.isdir(os.path.join(DATASET_ROOT, d))
])

print(f'Found {len(person_dirs)} identities in {DATASET_ROOT}')

for person_idx, person_id in enumerate(person_dirs):
    person_dir  = os.path.join(DATASET_ROOT, person_id)
    image_files = [
        fname for fname in os.listdir(person_dir)
        if fname.lower().endswith(('.jpg', '.jpeg', '.png'))
    ]

    embeddings = []
    for fname in image_files:
        img = cv2.imread(os.path.join(person_dir, fname))
        if img is None:
            continue
        faces = app.get(img)
        if not faces:
            continue
        # Take the largest detected face if multiple are present
        face = max(faces, key=lambda fc: (fc.bbox[2]-fc.bbox[0]) * (fc.bbox[3]-fc.bbox[1]))
        embeddings.append(face.normed_embedding.tolist())  # 512-D, L2-normalised

    if not embeddings:
        print(f'  [{person_idx+1}/{len(person_dirs)}] {person_id}: no faces detected, skipping')
        continue

    facial_data[person_id] = embeddings

    if (person_idx + 1) % 50 == 0 or (person_idx + 1) == len(person_dirs):
        print(f'  [{person_idx+1}/{len(person_dirs)}] {person_id}: {len(embeddings)} embeddings')

# -- Save -----------------------------------------------------------------
with open(OUTPUT_PATH, 'w') as f:
    json.dump(facial_data, f)

total_embs = sum(len(v) for v in facial_data.values())
print(f'Saved {len(facial_data)} identities, {total_embs} embeddings -> {OUTPUT_PATH}')
