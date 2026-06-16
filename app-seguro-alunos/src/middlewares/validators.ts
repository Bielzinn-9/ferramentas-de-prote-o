import { body, validationResult } from "express-validator";

export const validarRegistro = [
  body("nome")
    .trim()
    .notEmpty()
    .withMessage("Nome é obrigatório")
    .escape(),

  body("email")
    .isEmail()
    .withMessage("E-mail inválido")
    .normalizeEmail(),

  body("senha")
    .isLength({ min: 6 })
    .withMessage("A senha deve ter pelo menos 6 caracteres"),
];

export const validarLogin = [
  body("email")
    .isEmail()
    .withMessage("E-mail inválido")
    .normalizeEmail(),

  body("senha")
    .notEmpty()
    .withMessage("Senha é obrigatória"),
];

export const validarComentario = [
  body("texto")
    .trim()
    .notEmpty()
    .withMessage("Comentário é obrigatório")
    .escape(),
];

export { validationResult };