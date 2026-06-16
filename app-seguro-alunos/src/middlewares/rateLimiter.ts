import rateLimit from "express-rate-limit";

export const limiterGeral = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100,
  message: "Muitas requisições. Tente novamente mais tarde.",
  standardHeaders: true,
  legacyHeaders: false,
});

export const limiterLogin = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5,
  message: "Muitas tentativas de login. Tente novamente em 15 minutos.",
  standardHeaders: true,
  legacyHeaders: false,
});