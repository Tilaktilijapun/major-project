import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
import pickle
import os

# Ensure the ml_models folder in the PROJECT ROOT exists
model_dir = os.path.join(os.path.dirname(__file__), '..', 'ml_models')
os.makedirs(model_dir, exist_ok=True)

# Step 1: Dummy dataset
np.random.seed(42)
X = np.random.rand(1000, 10)
y = np.random.randint(0, 2, 1000)

# Step 2: Scale data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Step 3: Save the scaler
with open(os.path.join(model_dir, 'scaler.pkl'), 'wb') as f:
    pickle.dump(scaler, f)

# Step 4: Split data
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Step 5: Define model
model = Sequential([
    Dense(32, activation='relu', input_shape=(10,)),
    Dense(16, activation='relu'),
    Dense(1, activation='sigmoid')
])
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Step 6: Train model
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.2)

# Step 7: Save model
model.save(os.path.join(model_dir, 'threat_model.h5'))

print("✅ Model and scaler saved to ml_models/")
