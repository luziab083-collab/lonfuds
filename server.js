require("dotenv").config();
const express=require("express"), cors=require("cors"), bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), Database=require("better-sqlite3");
const db=new Database("lonfuds.db"); db.pragma("foreign_keys=ON");
db.exec(require("fs").readFileSync("schema.sql","utf8"));
const app=express(); app.use(cors()); app.use(express.json());
const SECRET=process.env.JWT_SECRET||"dev-secret-change-me";
const sign=u=>jwt.sign({id:u.id,role:u.role},SECRET,{expiresIn:"7d"});
function auth(req,res,next){try{req.user=jwt.verify((req.headers.authorization||"").replace("Bearer ",""),SECRET);next()}catch(e){res.status(401).json({error:"Não autorizado"})}}
app.get("/api/health",(req,res)=>res.json({ok:true,service:"lonfuds-api"}));
app.post("/api/auth/register",async(req,res)=>{
 const {name,phone,email,password}=req.body;
 if(!name||!phone||!password)return res.status(400).json({error:"Nome, telefone e senha são obrigatórios"});
 try{const hash=await bcrypt.hash(password,12);const info=db.prepare("INSERT INTO users(name,phone,email,password_hash) VALUES(?,?,?,?)").run(name,phone,email||null,hash);const u=db.prepare("SELECT id,name,phone,email,role FROM users WHERE id=?").get(info.lastInsertRowid);res.status(201).json({user:u,token:sign(u)})}
 catch(e){res.status(409).json({error:"Telefone ou e-mail já cadastrado"})}
});
app.post("/api/auth/login",async(req,res)=>{
 const {phone,password}=req.body;const u=db.prepare("SELECT * FROM users WHERE phone=?").get(phone);
 if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Credenciais inválidas"});
 const safe={id:u.id,name:u.name,phone:u.phone,email:u.email,role:u.role};res.json({user:safe,token:sign(safe)});
});
app.get("/api/me",auth,(req,res)=>res.json(db.prepare("SELECT id,name,phone,email,role FROM users WHERE id=?").get(req.user.id)));
app.get("/api/partners",(req,res)=>res.json(db.prepare("SELECT * FROM partners WHERE active=1 ORDER BY name").all()));
app.get("/api/partners/:id/products",(req,res)=>res.json(db.prepare("SELECT * FROM products WHERE partner_id=? AND active=1").all(req.params.id)));
app.post("/api/orders",auth,(req,res)=>{
 const {partnerId,type="food",pickupAddress,deliveryAddress,items=[]}=req.body;
 const total=items.reduce((s,i)=>s+Number(i.unitPrice)*Number(i.quantity||1),0);
 const tx=db.transaction(()=>{const o=db.prepare("INSERT INTO orders(user_id,partner_id,type,pickup_address,delivery_address,total) VALUES(?,?,?,?,?,?)").run(req.user.id,partnerId||null,type,pickupAddress||null,deliveryAddress||null,total);
 const stmt=db.prepare("INSERT INTO order_items(order_id,product_id,name,quantity,unit_price) VALUES(?,?,?,?,?)");
 for(const i of items)stmt.run(o.lastInsertRowid,i.productId||null,i.name,i.quantity||1,i.unitPrice);
 return o.lastInsertRowid});res.status(201).json(db.prepare("SELECT * FROM orders WHERE id=?").get(tx()));
});
app.get("/api/orders",auth,(req,res)=>res.json(db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.user.id)));
app.post("/api/deliveries",auth,(req,res)=>{
 const {pickupAddress,deliveryAddress}=req.body;if(!pickupAddress||!deliveryAddress)return res.status(400).json({error:"Endereços obrigatórios"});
 const o=db.prepare("INSERT INTO orders(user_id,type,status,pickup_address,delivery_address,total) VALUES(?,?,'searching',?,?,?)").run(req.user.id,"delivery",pickupAddress,deliveryAddress,9.9);
 res.status(201).json(db.prepare("SELECT * FROM orders WHERE id=?").get(o.lastInsertRowid));
});
app.post("/api/rides",auth,(req,res)=>{
 const {origin,destination,category="economy"}=req.body;if(!origin||!destination)return res.status(400).json({error:"Origem e destino obrigatórios"});
 const prices={economy:12.5,comfort:18.9,premium:26.9};const price=prices[category]||12.5;
 const r=db.prepare("INSERT INTO rides(user_id,origin,destination,category,price) VALUES(?,?,?,?,?)").run(req.user.id,origin,destination,category,price);
 res.status(201).json(db.prepare("SELECT * FROM rides WHERE id=?").get(r.lastInsertRowid));
});
app.get("/api/rides",auth,(req,res)=>res.json(db.prepare("SELECT * FROM rides WHERE user_id=? ORDER BY id DESC").all(req.user.id)));
app.listen(process.env.PORT||3000,()=>console.log("Lonfuds API rodando na porta "+(process.env.PORT||3000)));
