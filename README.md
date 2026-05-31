# Smart Wazuh SOC - Attack Classification Baseline

Pipeline penelitian untuk parsing multi-source Wazuh alerts dan baseline klasifikasi serangan `ddos`, `xss`, `sqli`.

## Scope

- Parse semua sumber dataset lokal (JSONL, JSON array, CSV flatten).
- Normalisasi atribut alert menjadi fitur training.
- Training baseline machine learning (RandomForest).
- Simpan model dan metrik evaluasi.

## Struktur File Utama

- `build_train_ready_all_sources.py`  
  Merge + parse semua source menjadi `train_ready_all_sources.csv`.
- `train_baseline_all_sources.py`  
  Train/evaluasi baseline dari dataset gabungan.
- `build_train_ready_full.py`  
  Parse full data khusus dari CSV utama.
- `train_baseline_full.py`  
  Train/evaluasi baseline dari `train_ready_full.csv`.
- `soc_wazuh_all_sources_baseline.ipynb`  
  Notebook end-to-end siap presentasi.

## Prasyarat

- Python 3.9+
- Paket Python:
  - `pandas`
  - `scikit-learn`
  - `joblib`
  - `matplotlib` (untuk notebook visualisasi)

Install dependency:

```bash
python3 -m pip install --user pandas scikit-learn joblib matplotlib
```

## Cara Menjalankan (Terminal)

Masuk ke folder project:

```bash
cd "/Volumes/SSD 850/PROJECTS/soc"
```

### Opsi A - All Sources (direkomendasikan)

1. Build dataset training dari semua source:

```bash
python3 build_train_ready_all_sources.py
```

Output:
- `parsed/train_ready_all_sources.csv`

2. Train baseline model:

```bash
python3 train_baseline_all_sources.py
```

Output:
- `parsed/model_all_sources/baseline_rf_all_sources.joblib`
- `parsed/model_all_sources/metrics_all_sources.json`

### Opsi B - Full CSV Utama Saja

1. Build dataset:

```bash
python3 build_train_ready_full.py
```

2. Train baseline:

```bash
python3 train_baseline_full.py
```

Output:
- `parsed/model_full/baseline_rf_full.joblib`
- `parsed/model_full/metrics_full.json`

## Cara Menjalankan (Jupyter Notebook)

Import dan jalankan:
- `soc_wazuh_all_sources_baseline.ipynb`

Atau pakai cell command:

```python
!python3 build_train_ready_all_sources.py
!python3 train_baseline_all_sources.py
!cat parsed/model_all_sources/metrics_all_sources.json
```

## Catatan Data

- Folder `Datasets/` tidak di-track git (ukuran besar, raw source).
- Folder `parsed/` juga tidak di-track (hasil generate, bisa direproduksi dari script).

## Ringkasan Flow

1. Raw alerts multi-source.
2. Parsing per format + normalisasi atribut.
3. Filtering label target (`ddos`, `xss`, `sqli`).
4. Feature engineering.
5. Train/test split.
6. Training RandomForest + evaluasi (accuracy, precision, recall, f1, confusion matrix).

