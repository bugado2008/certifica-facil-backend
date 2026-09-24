# Certifica Fácil — Backend

Este backend substitui o `localStorage` por uma API com banco SQLite.

## 1. Instalar

Tenha Node.js instalado e execute:

```bash
npm install
```

## 2. Iniciar

```bash
npm start
```

A API ficará em:

```text
http://localhost:3000
```

## 3. Principais rotas

- POST `/api/auth/register` — criar conta
- POST `/api/auth/login` — entrar
- GET `/api/me` — usuário logado
- GET `/api/classes` — turmas
- POST `/api/classes` — professor cria turma
- POST `/api/classes/join` — aluno entra com código
- GET `/api/classes/:id/activities` — atividades
- POST `/api/classes/:id/activities` — professor cria atividade
- POST `/api/activities/:id/submit` — aluno entrega
- GET `/api/activities/:id/submissions` — professor vê entregas
- POST `/api/submissions/:id/validate` — professor valida
- GET `/api/certificates` — certificados do aluno
- GET `/api/certificates/public/:token` — validação pública do certificado

## Importante

As senhas não são salvas em texto puro: o backend usa `bcryptjs` para armazenar um hash.

Antes de publicar, defina uma variável de ambiente `JWT_SECRET` com uma chave longa e aleatória.
