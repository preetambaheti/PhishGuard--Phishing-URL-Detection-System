# model.py — Minimal: Train & Save Tuned Random Forest Model
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import joblib

# Load and preprocess dataset
df = pd.read_csv("Phishing_Websites_Data.csv")
df = df.drop(columns=[col for col in ['Domain_registeration_length', 'age_of_domain'] if col in df.columns])
df['Result'] = df['Result'].map({-1: 1, 1: 0})
X = df.drop('Result', axis=1)
y = df['Result']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# Hyperparameter tuning for Random Forest
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5, 10]
}
grid_search = GridSearchCV(
    estimator=RandomForestClassifier(random_state=42),
    param_grid=param_grid,
    cv=5,
    n_jobs=-1,
    scoring='accuracy'
)
grid_search.fit(X_train, y_train)
best_model = grid_search.best_estimator_

# Evaluate and save model
y_pred = best_model.predict(X_test)
accuracy_score(y_test, y_pred)

joblib.dump(best_model, "phishing_model_best.pkl")
joblib.dump(scaler, "scaler.pkl")
