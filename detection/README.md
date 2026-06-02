# Pôle 1 — Machine Learning Detection (Khadija)

This directory is reserved for Khadija's Machine Learning model training pipelines and trained model objects.

## Integration Guidelines

1. **Model Storage**: Drop your trained models (e.g., `.pkl` or `.joblib` files) here or in a `models/` subfolder.
2. **Feature Alignment**: Ensure your model is trained or aligned to accept exactly the **12 features** defined in `config.py` in the exact order specified.
3. **Usage**: The capture pipeline or bridge daemon will load models from here using `joblib` or `pickle` for real-time predictions.
