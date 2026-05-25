import pandas as pd, numpy as np, joblib, os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from extract_features import extract_features
import shap
import matplotlib.pyplot as plt

df = pd.read_csv("sample_dataset.csv")
X = [extract_features(u) for u in df['url'].fillna('')]
y = df['label'].astype(int).values
X = np.array(X)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print("Accuracy:", acc)
print(classification_report(y_test, y_pred))
joblib.dump(model, "phishing_model.pkl")
print("Saved model to phishing_model.pkl")

explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X)
shap.summary_plot(shap_values, X, show=False)
plt.savefig("model_feature_importance.png", bbox_inches='tight')
plt.close()
print("SHAP plot saved as model_feature_importance.png")