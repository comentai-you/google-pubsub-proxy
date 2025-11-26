import { jwtVerify, createRemoteJWKSet } from 'jose';

// --- VARIÁVEIS DE AMBIENTE (CONFIGURADAS NO VERCEL) ---
// O URL LIMPO da sua Edge Function no Supabase
const TARGET_SUPABASE_URL = process.env.SUPABASE_RTDN_URL; 
// O Audience que o Google assina
const RTDN_AUDIENCE = process.env.RTDN_AUDIENCE; 
// A chave secreta COMPARTILHADA (para validação dentro do seu código Supabase)
const SUPABASE_SECRET = process.env.SUPABASE_SECRET; 
// A CHAVE MESTRA DO SUPABASE (para bypassar o firewall de autenticação)
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY; 

const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const JWKS = createRemoteJWKSet(new URL(JWKS_URL), { 
    caching: true, 
    maxAge: 60000 
});

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }
    
    // 1. CHECAGENS INICIAIS DE CONFIGURAÇÃO
    if (!SUPABASE_SECRET || !SUPABASE_SERVICE_KEY) {
        console.error('❌ Configuração de Chaves Secreta/Serviço ausente no Vercel.');
        return res.status(500).send('Proxy Misconfigured: Missing Secrets');
    }

    // 2. VALIDAÇÃO JWT DO GOOGLE (Segurança de quem enviou)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.error('❌ Cabeçalho de Autorização JWT ausente ou inválido.');
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
        // Retorna 200 OK para o Google para evitar o loop de retentativa
        return res.status(200).send('JWT Validation Failed, but acknowledged.');
    }
    
    // 3. PROXY PARA O SUPABASE (Injetando Chave Secreta e Header de Serviço)
    try {
        const payload = req.body; 
        
        // Constrói o URL de destino com a chave secreta (para seu código Supabase)
        const finalSupabaseUrl = `${TARGET_SUPABASE_URL}?secret=${SUPABASE_SECRET}`;

        const response = await fetch(finalSupabaseUrl, {
            method: 'POST',
            headers: {
                // LINHA CRÍTICA: Bypassa o erro 'Missing authorization header' do Gateway Supabase
                'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`, 
                'User-Agent': req.headers['user-agent'], 
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });

        const supabaseResponse = await response.json().catch(() => ({}));
        
        if (response.status >= 400) {
            console.error(`❌ Erro no Supabase: ${response.status}`, supabaseResponse);
        } else {
            console.log('✅ Requisição enviada com sucesso para o Supabase.');
        }

        // Retorna o status final do Supabase para o Google via Vercel
        return res.status(response.status).json(supabaseResponse);

    } catch (error) {
        console.error('❌ Falha ao redirecionar para Supabase:', error);
        return res.status(500).send('Proxy Failed');
    }
}