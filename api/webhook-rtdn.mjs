import { jwtVerify, createRemoteJWKSet } from 'jose';

// --- VARIÁVEIS DE AMBIENTE (CONFIGURADAS NO VERCEL) ---
// O URL LIMPO da sua Edge Function no Supabase (ex: https://jhhbhzwhicatcgvzgnuu.supabase.co/functions/v1/webhook-rtdn)
const TARGET_SUPABASE_URL = process.env.SUPABASE_RTDN_URL; 
// O Audience que o Google assina (ex: google-pubsub-proxy.vercel.app/api/webhook-rtdn)
const RTDN_AUDIENCE = process.env.RTDN_AUDIENCE; 
// A chave secreta COMPARTILHADA entre Vercel e Supabase
const SUPABASE_SECRET = process.env.SUPABASE_SECRET; 

const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const JWKS = createRemoteJWKSet(new URL(JWKS_URL), { 
    caching: true, 
    maxAge: 60000 
});

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }
    
    // 1. CHECAGEM DE CHAVE SECRETA (Se o Vercel não tiver, para o processo)
    if (!SUPABASE_SECRET) {
        console.error('❌ SUPABASE_SECRET não configurado no Vercel.');
        return res.status(500).send('Proxy Misconfigured');
    }

    // 2. VALIDAÇÃO JWT DO GOOGLE (Segurança de quem enviou)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.error('❌ Cabeçalho de Autorização ausente ou inválido.');
        return res.status(401).send('Unauthorized: Missing JWT');
    }

    const token = authHeader.replace('Bearer ', '');
    try {
        await jwtVerify(token, JWKS, {
            issuer: "https://accounts.google.com",
            audience: RTDN_AUDIENCE,
        });
        console.log('✅ JWT Validado com sucesso no Vercel.');

    } catch (error) {
        console.error('❌ Falha na Validação do JWT (Token Inválido):', error.message);
        // Retorna 200 OK para o Google para evitar o loop de retentativa, mas loga a falha.
        return res.status(200).send('JWT Validation Failed, but acknowledged.');
    }
    
    // 3. PROXY PARA O SUPABASE (Adicionando a Chave Secreta)
    try {
        const payload = req.body; 
        
        // Constrói o URL de destino com a chave secreta
        const finalSupabaseUrl = `${TARGET_SUPABASE_URL}?secret=${SUPABASE_SECRET}`;

        const response = await fetch(finalSupabaseUrl, {
            method: 'POST',
            headers: {
                // Passamos o User-Agent e o Content-Type
                'User-Agent': req.headers['user-agent'], 
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });

        // Tenta ler a resposta do Supabase para repassar o status/corpo
        const supabaseResponse = await response.json().catch(() => ({}));
        
        if (response.status >= 400) {
            console.error(`❌ Erro no Supabase: ${response.status}`, supabaseResponse);
        } else {
            console.log('✅ Requisição enviada com sucesso para o Supabase.');
        }

        // Retorna o status do Supabase para o Google
        return res.status(response.status).json(supabaseResponse);

    } catch (error) {
        console.error('❌ Falha ao redirecionar para Supabase:', error);
        return res.status(500).send('Proxy Failed');
    }
}