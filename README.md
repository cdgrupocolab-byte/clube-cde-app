# Clube CDE — Área de Membros

Protótipo funcional do app do Clube CDE: mapa de rede, mural, trilhas, ferramentas/calculadoras, O Conselho, especialistas de IA, materiais e tela de login. Tudo em um único arquivo `index.html` autocontido (HTML + CSS + JS, sem dependências externas).

## Como funciona o login (importante)

A tela de login é **só a fachada** por enquanto. Não existe backend, banco de dados nem senha real sendo validada. Qualquer e-mail válido + senha com 6 ou mais caracteres entra — isso é proposital, pra dar pra qualquer pessoa testar o app sem precisar de credencial de verdade.

Quando for integrar com um gateway de pagamento de verdade (Hotmart, Eduzz, Stripe, Asaas etc.), o fluxo real é:

1. Gateway aprova a assinatura → dispara um webhook
2. Webhook chama seu backend → cria a conta do membro
3. O formulário de login (`#login-form` no `index.html`) passa a enviar os dados pra esse backend de verdade
4. Sessão vira cookie/token seguro no lugar do `localStorage` atual

## Deploy no Render

Este repositório já vem com um `render.yaml` (Blueprint do Render), então o deploy é automático assim que o repo estiver conectado:

1. Suba este repositório pro GitHub (veja os comandos abaixo)
2. No [Render](https://dashboard.render.com), clique em **New +** → **Blueprint**
3. Conecte este repositório
4. Clique em **Apply** — o Render lê o `render.yaml` sozinho e sobe o site como Static Site, de graça

Se preferir sem Blueprint: **New +** → **Static Site** → conecta o repo → deixa "Build Command" vazio → "Publish Directory" = `.` (raiz) → **Create Static Site**.

O Render te dá uma URL tipo `https://clube-cde.onrender.com` — é esse link que você manda pras pessoas.

## Como atualizar o site depois

Edite `index.html`, depois:

```
git add index.html
git commit -m "atualiza o app"
git push
```

O Render redesenha automaticamente a cada push (deploy contínuo).

## Estrutura

- `index.html` — o app inteiro (front-end puro, sem build)
- `render.yaml` — configuração de deploy do Render
