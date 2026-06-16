import express from "express";
import session from "express-session";
import helmet from "helmet";
import cors from "cors";
import { readFileSync, writeFileSync } from "fs";
import { body } from "express-validator";

import { limiterGeral, limiterLogin } from "./middlewares/rateLimiter";
import {
  validarRegistro,
  validarLogin,
  validationResult,
} from "./middlewares/validators";
import { Request } from "express-validator/lib/base";

const app = express();

/* =========================
   SEGURANÇA
========================= */
app.use(helmet());
app.use(cors());
app.use(limiterGeral);

/* =========================
   PARSERS
========================= */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =========================
   SESSION
========================= */
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret-super-forte-123456",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60 * 1000,
      httpOnly: true,
      secure: false,
    },
  })
);

app.set("view engine", "ejs");
app.set("views", "./src/views");
app.use(express.static("public"));

function carregarUsers() {
  try {
    return JSON.parse(readFileSync("dados/usuarios.json", "utf-8"));
  } catch {
    return [];
  }
}

function salvarUsers(u: any[]) {
  writeFileSync("dados/usuarios.json", JSON.stringify(u, null, 2));
}

function carregarComentarios() {
  try {
    return JSON.parse(readFileSync("dados/comentarios.json", "utf-8"));
  } catch {
    return [];
  }
}

function salvarComentarios(c: any[]) {
  writeFileSync("dados/comentarios.json", JSON.stringify(c, null, 2));
}

// LOGIN
app.get("/login", (req, res) => {
  const flash = req.session.flash || null;
  req.session.flash = null;
  res.render("login", { flash });
});

app.post("/login", limiterLogin, validarLogin, (req: Request, res: { redirect: (arg0: string) => void; }) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    req.session.flash = errors.array()[0].msg;
    return res.redirect("/login");
  }

  const { email, senha } = req.body;

  const users = carregarUsers();

  const user = users.find(
    (u: any) => u.email === email && u.senha === senha
  );

  if (!user) {
    req.session.flash = "Email não encontrado ou senha errada.";
    return res.redirect("/login");
  }

  req.session.userId = user.id;
  req.session.userName = user.nome;
  req.session.userRole = user.role;

  res.redirect("/");
});
// REGISTRO
app.get("/registro", (req, res) => {
  res.render("registro", { flash: null });
});

app.post("/registro", validarRegistro, (req: Request, res: { redirect: (arg0: string) => void; }) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    req.session.flash = errors.array()[0].msg;
    return res.redirect("/registro");
  }

  const { nome, email, senha } = req.body;

  const users = carregarUsers();

  users.push({
    id: users.length + 1,
    nome,
    email,
    senha,
    role: "user",
  });

  salvarUsers(users);

  req.session.flash = "Conta criada!";
  res.redirect("/login");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

// HOME + COMENTÁRIOS
app.get("/", (req, res) => {
  if (!req.session.userId) {
    res.redirect("/login");
    return;
  }

  const comentarios = carregarComentarios();

  const flash = req.session.flash || null;
  req.session.flash = null;

  res.render("home", {
    nome: req.session.userName,
    role: req.session.userRole,
    comentarios,
    flash,
  });
});

app.post(
  "/comentar",
  body("texto")
    .trim()
    .notEmpty()
    .withMessage("Comentário obrigatório")
    .escape(),

  (req, res) => {
    if (!req.session.userId) {
      return res.redirect("/login");
    }

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      req.session.flash = errors.array()[0].msg;
      return res.redirect("/");
    }

    const coments = carregarComentarios();

    coments.push({
      id: coments.length + 1,
      userId: req.session.userId,
      autor: req.session.userName,
      texto: req.body.texto,
      data: new Date().toLocaleDateString("pt-BR"),
    });

    salvarComentarios(coments);

    res.redirect("/");
  }
);
// EDITAR COMENTÁRIO
app.post("/comentarios/:id/editar", (req, res) => {
  if (!req.session.userId) {
    res.redirect("/login");
    return;
  }

  const coments = carregarComentarios();

  const c = coments.find(
    (c: any) => c.id === Number(req.params.id)
  );

  // ⚠️ VULNERABILIDADE 8: IDOR — não verifica se é o dono!
  if (c) {
    c.texto = req.body.texto;
    salvarComentarios(coments);
  }

  res.redirect("/");
});

// REMOVER COMENTÁRIO
app.post("/comentarios/:id/remover", (req, res) => {
  if (!req.session.userId) {
    res.redirect("/login");
    return;
  }

  let coments = carregarComentarios();

  // ⚠️ VULNERABILIDADE 9: IDOR — não verifica se é o dono!
  coments = coments.filter(
    (c: any) => c.id !== Number(req.params.id)
  );

  salvarComentarios(coments);

  res.redirect("/");
});

// API USUÁRIOS
app.get("/api/usuarios", (req, res) => {
  const users = carregarUsers();

  // ⚠️ VULNERABILIDADE 10: retorna SENHA na resposta!
  res.json(users);
});

// ADMIN (sem guard!)
app.get("/admin", (req, res) => {
  // ⚠️ VULNERABILIDADE 11: sem requireRole!
  if (!req.session.userId) {
    res.redirect("/login");
    return;
  }

  res.render("admin", {
    usuarios: carregarUsers(),
    flash: null,
  });
});

app.listen(3000, () => {
  console.log(
    "⚠️ App VULNERÁVEL rodando (NÃO usar em produção!)"
  );
});