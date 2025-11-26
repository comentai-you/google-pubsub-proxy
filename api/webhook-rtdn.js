// api/webhook-rtdn.js
import { jwtVerify, createRemoteJWKSet } from 'jose';

// --- VARIÁVEIS DE AMBIENTE (CONFIGURADAS NO VERCEL) ---
const TARGET_SUPABASE_URL = process.env.SUPABASE_RTDN_URL; 
const RTDN_AUDIENCE = process.env.RTDN_AUDIENCE; 
const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

const JWKS = createRemoteJWKSet(new URL(JWKS_URL), { 
    caching: true, 
    maxAge: 60000 
});

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }
    
    // --- 1. VALIDAÇÃO JWT ---
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Se o Google não enviou o JWT, rejeita
        console.error('Missing or Invalid Authorization Header');
        return res.status(401).send('Unauthorized: Missing JWT');
    }

    const token = authHeader.replace('Bearer ', '');
    try {
        await jwtVerify(token, JWKS, {
            issuer: "https://accounts.google.com",
            audience: RTDN_AUDIENCE, // O Audience que você configurará no GCP
        });
        console.log('✅ JWT Validado com sucesso no Vercel.');

    } catch (error) {
        console.error('❌ Falha na Validação do JWT no Vercel:', error.message);
        // Retorna 200 OK para evitar loops de retry no Pub/Sub, mas loga a falha
        return res.status(200).send('JWT Validation Failed, but acknowledged.');
    }
    
    // --- 2. PROXY PARA O SUPABASE (Limpo) ---
    try {
        const payload = req.body; 

        // Repassa a mensagem. Importante: NÃO REPASSA o cabeçalho Authorization.
        const response = await fetch(TARGET_SUPABASE_URL, {
            method: 'POST',
            headers: {
                'User-Agent': req.headers['user-agent'], 
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });

        // Retorna o status/corpo do Supabase para o Google
        const supabaseResponse = await response.json().catch(() => ({}));
        
        return res.status(response.status).json(supabaseResponse);

    } catch (error) {
        console.error('❌ Falha ao redirecionar para Supabase:', error);
        return res.status(500).send('Proxy Failed');
    }
}