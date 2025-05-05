""" Initial stuff - imports, loading the dataset"""
import joblib
import pandas as pd
import numpy as np

# Classifiers
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from xgboost import XGBClassifier
import shap

# Training + test split
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn import preprocessing
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler

# Accuracy score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support

# Oversampling
from imblearn.over_sampling import RandomOverSampler

# GridSearchCV + RandomizedSearchCV for searching of hyperparameters
from sklearn.model_selection import RandomizedSearchCV
from sklearn.model_selection import GridSearchCV


# Loading the dataset
df = pd.read_csv("scripts\\classification\\datasets\\dataset.csv", header=0, na_values=["?"])

""" Preprocessing the dataset - cleaning, target encoding, retyping, dropping NaN """

# Removing NaN values
df.dropna(inplace=True)

target_cols = ["Registrar", "SSL_Issuer", "Server", "Location"]

# Target encodings for main.py to use
target_encodings = {}

# Calculating the global mean of Class
global_mean = df["Class"].mean()

# Smoothing factor
m = 3  

# Target Encoding + Smoothing
for col in target_cols:
    # Compute category mean
    encoding = df.groupby(col)["Class"].mean()
    
    # Compute category size
    counts = df.groupby(col)["Class"].count()
    
    # Apply smoothing formula
    smoothed_encoding = (encoding * counts + m * global_mean) / (counts + m)
    
    # Store encoding for main.py
    target_encodings[col] = smoothed_encoding
    
    # Apply encoding to the dataset (fill new categories with global mean)
    df[col] = df[col].map(smoothed_encoding).fillna(global_mean)



# Domain name doesn't aid in the training so we drop it + Class is the target
X = df.drop(columns=['Domain', 'Class'])

# Convert boolean columns to integers
bool_columns = X.select_dtypes(include=['bool']).columns
for col in bool_columns:
    X[col] = X[col].astype(int)

y = df["Class"]


# Applying imbalanced-learn, to add more samples to the malicious domains
ros = RandomOverSampler(random_state=0)
X_resampled, y_resampled = ros.fit_resample(X, y)


""" Dividing the preprocessed dataset into training and testing split - testing is 40% """
X_train, X_test, y_train, y_test = train_test_split(X_resampled, y_resampled, test_size=0.4, random_state=42)



""" ====== Logistic Regression ====== """

scaler = StandardScaler()
X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns)
X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns)

# Train Logistic Regression
log_reg = LogisticRegression(penalty='l1', solver='liblinear', C=1.0, max_iter=5000)
log_reg.fit(X_train_scaled, y_train)

# Predictions
y_pred_lr = log_reg.predict(X_test_scaled)

# Evaluation
test_score_lr = accuracy_score(y_test, y_pred_lr)
print("--- Logistic Regression ---")
print("Test Accuracy:", test_score_lr)
print("Precision, F1, Recall, Support - LR")
print(classification_report(y_test, y_pred_lr, digits=5))
print("Confusion Matrix")
print(confusion_matrix(y_test, y_pred_lr))

""" ====== Random Forest ====== """
rf = RandomForestClassifier(
    # Hyperparameters
    n_estimators=300,
    max_depth=20,
    max_features='log2',
    min_samples_leaf=1,
    min_samples_split=2,
    bootstrap=True
)

# Cross-validation score RF
cv_score_rf = cross_val_score(rf, X_train, y_train, cv=10, scoring='accuracy')

# Training RF
rf.fit(X_train, y_train)

# Prediction RF
y_pred_rf = rf.predict(X_test)

# # Evaluation RF
test_score_rf = accuracy_score(y_test, y_pred_rf)
print("\n--- Random Forest ---")
print("Cross-validation scores:", cv_score_rf)
print("Average CV Score:", cv_score_rf.mean())

# Accuracy RF
print("Test Accuracy:", test_score_rf)

print("Precision, F1, Recall, Support - RF")
print(classification_report(y_test, y_pred_rf, digits=5))

print("Confusion Matrix")
cm = confusion_matrix(y_test, y_pred_rf)
print(cm)



""" ====== XGB ====== """
xgb = XGBClassifier(
    # Hyperparameters
    eval_metric="logloss",
    subsample = 0.9,
    reg_lambda = 1,
    reg_alpha = 0,
    n_estimators = 350, 
    min_child_weight = 1, 
    max_depth = 100, 
    gamma = 0.3, 
    colsample_bytree = 0.3)

# Cross-Validation score XGB
cv_score_xgb = cross_val_score(xgb, X_train, y_train, cv=10, scoring='accuracy') 

# Training XGB
xgb.fit(X_train, y_train)

# Prediction XGB
y_pred_xgb = xgb.predict(X_test)

test_score_xgb = accuracy_score(y_test, y_pred_xgb)
print("\n--- XGBoost ---")
print("Cross-validation scores:", cv_score_xgb)
print("Average CV Score:", cv_score_xgb.mean())

# Accuracy XGB
print("Test Accuracy:", test_score_xgb)

print("Precision, F1, Recall, Support - XGB")
print(classification_report(y_test, y_pred_xgb, digits=5))

print("Confusion Matrix")
cm = confusion_matrix(y_test, y_pred_xgb)
print(cm)

# SHAP
explainer = shap.Explainer(xgb) 
shap_values = explainer(X_train)

shap_importance = np.mean(np.abs(shap_values.values), axis=0)
feature_importance = dict(zip(X_train.columns, shap_importance))

sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)
print("Top important features according to SHAP values:")
for feature, importance in sorted_features[:30]: 
    print(f"{feature}: {importance}")

# Save trained models
try:
    joblib.dump(log_reg, "scripts\\classification\\models\\log_reg_model.pkl")
    joblib.dump(rf, "scripts\\classification\\models\\rf_model.pkl")
    joblib.dump(xgb, "scripts\\classification\\models\\xgb_model.pkl")

    # Save target encoding and global mean
    joblib.dump(target_encodings, "scripts\\classification\\models\\target_encodings.pkl")
    joblib.dump(global_mean, "scripts\\classification\\models\\global_mean.pkl")

    # Save StandardScaler used for LR
    scaler = StandardScaler()
    scaler.fit(X_train)
    joblib.dump(scaler, "scripts\\classification\\models\\scaler.pkl")

    print("\nModels trained and saved successfully!")

except Exception as e: 
    print("There was a problem with saving the models.")