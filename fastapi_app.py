from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
from datetime import datetime
import asyncio
import json
from app.ml.threat_detection import ThreatDetectionModel
from sqlalchemy.orm import Session
from models import Threat, Alert, Device
from extensions import db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import redis
import os

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:kushal07@localhost:5432/aivivid')
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Redis configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost')
redis_client = redis.from_url(REDIS_URL)

app = FastAPI(
    title="AIVivid Security API",
    description="FastAPI service for ML-powered cybersecurity operations",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize ML model
threat_detection_model = ThreatDetectionModel()

# WebSocket manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.alert_channels: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: Optional[str] = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        if channel:
            if channel not in self.alert_channels:
                self.alert_channels[channel] = []
            self.alert_channels[channel].append(websocket)

    def disconnect(self, websocket: WebSocket, channel: Optional[str] = None):
        self.active_connections.remove(websocket)
        if channel and channel in self.alert_channels:
            self.alert_channels[channel].remove(websocket)

    async def broadcast(self, message: str, channel: Optional[str] = None):
        if channel and channel in self.alert_channels:
            for connection in self.alert_channels[channel]:
                try:
                    await connection.send_text(message)
                except:
                    continue
        else:
            for connection in self.active_connections:
                try:
                    await connection.send_text(message)
                except:
                    continue

manager = ConnectionManager()

# Pydantic models
class NetworkData(BaseModel):
    src_ip: str
    dst_ip: str
    protocol_type: str
    service: str
    packet_size: int
    src_bytes: int
    dst_bytes: int
    flags: str
    additional_features: Optional[Dict] = None

class ThreatAlert(BaseModel):
    threat_type: str
    severity: str
    confidence: float
    source_ip: str
    destination_ip: str
    timestamp: datetime
    details: Dict
    recommendations: List[str]

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# WebSocket endpoint for real-time monitoring
@app.websocket("/ws/threats/{channel}")
async def websocket_endpoint(websocket: WebSocket, channel: str):
    await manager.connect(websocket, channel)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                network_data = json.loads(data)
                detection_result = threat_detection_model.detect_threat(network_data)
                
                if "error" not in detection_result:
                    # Store in Redis for caching
                    redis_key = f"threat:{detection_result['timestamp']}"
                    redis_client.setex(redis_key, 3600, json.dumps(detection_result))
                    
                    # Broadcast to all connected clients in the channel
                    await manager.broadcast(
                        json.dumps(detection_result),
                        channel
                    )
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"error": "Invalid JSON data"}))
            except Exception as e:
                await websocket.send_text(json.dumps({"error": str(e)}))
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)

# REST endpoints
@app.post("/api/detect-threat", response_model=ThreatAlert)
async def detect_threat(
    network_data: NetworkData,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    try:
        # Convert Pydantic model to dict for ML model
        data_dict = network_data.dict()
        
        # Detect threat using ML model
        detection_result = threat_detection_model.detect_threat(data_dict)
        
        if "error" in detection_result:
            raise HTTPException(status_code=500, detail=detection_result["error"])
        
        # Create threat record
        threat = Threat(
            name=detection_result["threat_type"],
            type=detection_result["threat_type"],
            severity=detection_result["severity"],
            description=detection_result["details"]["alert_message"],
            status="Active",
            indicator=f"src_ip={network_data.src_ip},dst_ip={network_data.dst_ip}"
        )
        db.add(threat)
        
        # Create alert
        alert = Alert(
            threat_id=threat.id,
            title=f"{detection_result['threat_type']} Detected",
            message=detection_result["details"]["alert_message"]
        )
        db.add(alert)
        db.commit()
        
        # Broadcast alert through WebSocket
        background_tasks.add_task(
            manager.broadcast,
            json.dumps(detection_result),
            "threats"
        )
        
        return ThreatAlert(**detection_result)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/ml/predict")
async def predict_threat(data: NetworkData, background_tasks: BackgroundTasks):
    try:
        # Process network data through ML model
        prediction = threat_detection_model.predict_threat(data.dict())
        
        # Create threat record if confidence is high
        if prediction['confidence'] > 0.7:
            threat = Threat(
                name=f"{prediction['threat_type']} Threat",
                type=prediction['threat_type'],
                severity="High" if prediction['confidence'] > 0.9 else "Medium",
                description=prediction['description'],
                affected_device=data.src_ip
            )
            db.session.add(threat)
            db.session.commit()
            
            # Broadcast alert
            alert_data = json.dumps({
                "type": "threat_detected",
                "data": prediction
            })
            background_tasks.add_task(manager.broadcast, alert_data, "alerts")
        
        return prediction
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/alerts/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket, "alerts")
    try:
        while True:
            data = await websocket.receive_text()
            # Process received data if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket, "alerts")

# Add real-time monitoring endpoints
@app.get("/api/monitoring/stats")
async def get_monitoring_stats():
    stats = {
        "active_threats": Threat.query.filter_by(status="Active").count(),
        "total_devices": Device.query.count(),
        "recent_alerts": Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    }
    return stats