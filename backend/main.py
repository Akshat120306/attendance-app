from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# 1️⃣ Create FastAPI app first
app = FastAPI()

# 2️⃣ Then add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"],
)



from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bson import ObjectId
from pymongo import MongoClient
import bcrypt, jwt, datetime, qrcode, io, base64, os

# -------------------
# Configuration
# -------------------
MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb+srv://akshatmaggon1_db:Akshat1234@attendance.xndiua8.mongodb.net/?retryWrites=true&w=majority&appName=attendance"
)
SECRET = os.getenv("JWT_SECRET", "supersecretkey")

# -------------------
# MongoDB connection
# -------------------
client = MongoClient(MONGO_URI)
db = client["attendance"]

# -------------------
# FastAPI setup
# -------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------
# Models
# -------------------
class User(BaseModel):
    name: str
    email: str
    password: str

class Login(BaseModel):
    email: str
    password: str

# -------------------
# Helpers
# -------------------
def hash_pw(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_pw(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

def create_token(user_id):
    payload = {
        "user_id": str(user_id),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def get_role(user_id, class_id):
    member = db.members.find_one({"userId": user_id, "classId": ObjectId(class_id)})
    return member["role"] if member else None

# -------------------
# Routes
# -------------------
@app.post("/signup")
def signup(user: User):
    if db.users.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = hash_pw(user.password)
    res = db.users.insert_one({"name": user.name, "email": user.email, "password": hashed})
    return {"token": create_token(res.inserted_id)}

@app.post("/login")
def login(user: Login):
    db_user = db.users.find_one({"email": user.email})
    if not db_user or not verify_pw(user.password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_token(db_user["_id"])}

@app.post("/create_class")
def create_class(name: str, token: str):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    join_code = str(ObjectId())[:6]
    res = db.classes.insert_one({
        "name": name,
        "createdBy": decoded["user_id"],
        "joinCode": join_code
    })
    db.members.insert_one({
        "classId": res.inserted_id,
        "userId": decoded["user_id"],
        "role": "teacher"
    })
    return {"classId": str(res.inserted_id), "joinCode": join_code}

@app.post("/join_class")
def join_class(joinCode: str, token: str):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    cls = db.classes.find_one({"joinCode": joinCode})
    if not cls:
        raise HTTPException(status_code=404, detail="Class not found")
    db.members.insert_one({
        "classId": cls["_id"],
        "userId": decoded["user_id"],
        "role": "student"
    })
    return {"msg": "Joined class successfully"}

@app.get("/my_classes")
def my_classes(token: str):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = decoded["user_id"]
    memberships = db.members.find({"userId": user_id})
    classes = []
    for m in memberships:
        cls = db.classes.find_one({"_id": m["classId"]})
        if cls:
            classes.append({
                "id": str(cls["_id"]),
                "name": cls["name"],
                "joinCode": cls["joinCode"],
                "role": m["role"]
            })
    return {"classes": classes}

@app.post("/start_session")
def start_session(classId: str, token: str, request: Request):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    session = {"classId": classId, "date": datetime.datetime.utcnow()}
    res = db.sessions.insert_one(session)
    session_id = str(res.inserted_id)

    # Generate QR with sessionId only (student will add their own token when scanning)
    base_url = str(request.base_url).rstrip("/")
    qr_data = f"{base_url}/mark_attendance_qr?sessionId={session_id}"

    img = qrcode.make(qr_data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return {"sessionId": session_id, "qr": f"data:image/png;base64,{qr_b64}"}

@app.post("/mark_attendance_qr")
def mark_attendance_qr(sessionId: str, token: str):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    session = db.sessions.find_one({"_id": ObjectId(sessionId)})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    role = get_role(decoded["user_id"], str(session["classId"]))
    if role != "student":
        raise HTTPException(status_code=403, detail="Only students can scan QR")
    
    if db.attendance.find_one({"sessionId": ObjectId(sessionId), "studentId": decoded["user_id"]}):
        raise HTTPException(status_code=400, detail="Attendance already recorded")
    
    db.attendance.insert_one({
        "sessionId": ObjectId(sessionId),
        "studentId": decoded["user_id"],
        "status": "present",
        "timestamp": datetime.datetime.utcnow(),
        "method": "qr"
    })
    return {"msg": "Attendance marked via QR"}

@app.get("/class_students")
def class_students(classId: str, token: str):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    role = get_role(decoded["user_id"], classId)
    if role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can view students")
    
    members = db.members.find({"classId": ObjectId(classId), "role": "student"})
    students = []
    for m in members:
        u = db.users.find_one({"_id": ObjectId(m["userId"])})
        if u:
            students.append({"id": str(u["_id"]), "name": u["name"], "email": u["email"]})
    return {"students": students}

@app.post("/teacher_mark_attendance")
def teacher_mark_attendance(classId: str, studentId: str, sessionId: str, token: str):
    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    role = get_role(decoded["user_id"], classId)
    if role != "teacher":
        raise HTTPException(status_code=403, detail="Only teachers can mark attendance")
    
    if db.attendance.find_one({"sessionId": ObjectId(sessionId), "studentId": studentId}):
        raise HTTPException(status_code=400, detail="Attendance already recorded")
    
    db.attendance.insert_one({
        "sessionId": ObjectId(sessionId),
        "studentId": studentId,
        "status": "present",
        "timestamp": datetime.datetime.utcnow(),
        "method": "teacher",
        "markedBy": decoded["user_id"]
    })
    return {"msg": "Attendance marked by teacher"}
