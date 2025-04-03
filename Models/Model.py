import pandas as pd
import numpy as np
from sklearn import preprocessing
from sklearn.preprocessing import StandardScaler
import joblib
from sklearn.model_selection import train_test_split,cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, classification_report

##########################################
# SECTION 1: IDS_Dataset Processing
##########################################

# Read IDS dataset (assumes header exists)
df_ids = pd.read_csv(r'../IDS_Dataset.csv', header=0)


df_ids = df_ids.drop(columns = ['Timestamp'])
# Replace infinite values and drop missing rows
df_ids.replace([np.inf, -np.inf], np.nan, inplace=True)
df_ids.dropna(inplace=True)

# Convert labels: 'Benign' -> 'normal'; all others -> 'attack'
df_ids['Label'] = df_ids['Label'].apply(lambda x: 'normal' if x == 'Benign' else 'attack')

# Separate features and target
y_ids = df_ids["Label"]
X_ids = df_ids.drop(columns=['Label'])

# Split IDS dataset into training and test sets
X_train_ids, X_test_ids, y_train_ids, y_test_ids = train_test_split(
    X_ids, y_ids, test_size=0.2, random_state=42
)

# Scale the IDS features
scaler_ids = StandardScaler()
X_train_scaled_ids = scaler_ids.fit_transform(X_train_ids)
X_test_scaled_ids = scaler_ids.transform(X_test_ids)

# Define multiple models for the IDS dataset
model = SVC()


model.fit(X_train_scaled_ids, y_train_ids)
y_pred_ids = model.predict(X_test_scaled_ids)
print(f"Accuracy: {accuracy_score(y_test_ids, y_pred_ids):.4f}")
print("Classification Report:\n", classification_report(y_test_ids, y_pred_ids))
cv_scores = cross_val_score(model, X_train_scaled_ids, y_train_ids, cv=5)

print(f"CV Accuracy: {cv_scores.mean():.4f}")

##########################################
# SECTION 2: NSL-KDD Dataset Processing
##########################################

# Read NSL-KDD dataset
df_nsl = pd.read_csv(r'../NSL-KDD/KDDTest+.txt', header=None)

# Define column names for NSL-KDD
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
           'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
           'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
           'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
           'num_access_files', 'num_outbound_cmds', 'is_host_login',
           'is_guest_login', 'count', 'srv_count', 'serror_rate',
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
           'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
           'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
           'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
           'dst_host_srv_rerror_rate', 'attack', 'level']
df_nsl.columns = columns

# Binary labeling: 'normal' remains; every other label becomes 'attack'
df_nsl['attack'] = df_nsl['attack'].apply(lambda x: x if x == 'normal' else 'attack')

# Identify and encode categorical features for NSL-KDD
categorical_cols = df_nsl.select_dtypes(include='object').columns
le = preprocessing.LabelEncoder()
for col in categorical_cols:
    df_nsl[col] = le.fit_transform(df_nsl[col])

# Prepare features and target for NSL-KDD
X_nsl = df_nsl.drop(["attack"], axis=1)
y_nsl = df_nsl["attack"]

# Split NSL-KDD into training and test sets
X_train_nsl, X_test_nsl, y_train_nsl, y_test_nsl = train_test_split(
    X_nsl, y_nsl, test_size=0.1, random_state=42
)

# Select important columns for NSL-KDD (as defined)
important_cols = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                  'dst_bytes', 'wrong_fragment', 'hot', 'logged_in', 'num_compromised',
                  'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
                  'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
                  'srv_diff_host_rate', 'dst_host_count']

X_train_nsl = X_train_nsl[important_cols]
X_test_nsl = X_test_nsl[important_cols]

# Scale the NSL-KDD features
scaler_nsl = StandardScaler()
X_train_scaled_nsl = scaler_nsl.fit_transform(X_train_nsl)
X_test_scaled_nsl = scaler_nsl.transform(X_test_nsl)

# Use pre-tuned Random Forest parameters for NSL-KDD (no grid search)
tuned_rf = RandomForestClassifier(
    n_estimators=300,
    min_samples_split=5,
    max_depth=None,
    min_samples_leaf=1,
    random_state=42
)

# Train the Random Forest on NSL-KDD
tuned_rf.fit(X_train_scaled_nsl, y_train_nsl)
y_pred_nsl = tuned_rf.predict(X_test_scaled_nsl)

print("\n----- NSL-KDD Random Forest Performance -----")
print(f"Accuracy: {accuracy_score(y_test_nsl, y_pred_nsl):.4f}")
print("Classification Report:\n", classification_report(y_test_nsl, y_pred_nsl))

# Save the NSL-KDD Random Forest model to disk
joblib.dump(tuned_rf, 'NSL_KDD_rf.pkl')
joblib.dump(model,'IDS_Model_svc.pkl')
joblib.dump(scaler_nsl, 'scaler_nsl.pkl')
joblib.dump(scaler_ids, 'scaler_ids.pkl')
joblib.dump(le, 'encodings.pkl')
print("\nNSL-KDD model saved as 'NSL_KDD_best_rf.pkl'")
