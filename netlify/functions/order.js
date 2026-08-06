// Fonction serverless Netlify — Reçoit la commande avec fichiers et relaie vers Brevo (UE, Paris).
// Gère les uploads multipart/form-data (fichiers PDF joints au formulaire).
// Clé API et config lues depuis les variables d'environnement Netlify — jamais commités.

const BUSBOY_LIMITS = { fileSize: 10 * 1024 * 1024 }; // 10 Mo par fichier

exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': 'https://bail-safe.netlify.app',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  // ── Parse multipart ou JSON ──
  let fields = {}, files = [];

  const contentType = event.headers['content-type'] || '';
  if (contentType.includes('multipart/form-data')) {
    try {
      const Busboy = require('busboy');
      const parsed = await new Promise((resolve, reject) => {
        const bb = Busboy({ headers: event.headers, limits: BUSBOY_LIMITS });
        const f = {}, fls = [];
        bb.on('field', (name, val) => { f[name] = val; });
        bb.on('file', (name, stream, info) => {
          const chunks = [];
          stream.on('data', chunk => chunks.push(chunk));
          stream.on('end', () => {
            fls.push({
              fieldName: name,
              filename: info.filename,
              mimeType: info.mimeType,
              buffer: Buffer.concat(chunks),
              size: Buffer.concat(chunks).length,
            });
          });
        });
        bb.on('close', () => resolve({ fields: f, files: fls }));
        bb.on('error', reject);
        bb.end(Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8'));
      });
      fields = parsed.fields;
      files = parsed.files;
    } catch (err) {
      console.error('Erreur parsing multipart:', err);
      return { statusCode: 400, body: JSON.stringify({ error: 'Formulaire invalide' }) };
    }
  } else {
    try {
      fields = JSON.parse(event.body || '{}');
    } catch {
      return { statusCode: 400, body: JSON.stringify({ error: 'JSON invalide' }) };
    }
  }

  const { name, email, phone, formule, document_type, message, gdpr_consent, gdpr_candidat_informe, retractation_renoncement } = fields;

  if (!name || !email || !document_type) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Champs requis manquants' }) };
  }

  const FORMULE_PRICES = {
    "Essentiel — 1 document (69 €)": 69,
    "Sécurisé — 2 documents (149 €)": 149,
    "Dossier Complet — jusqu'à 4 documents (299 €)": 299
  };
  const montant = FORMULE_PRICES[formule] || 59;

  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  const senderName = process.env.BREVO_SENDER_NAME || 'BailSafe';
  const notifEmail = process.env.BAILSAFE_NOTIF_EMAIL || 'contact.bailsafe@gmail.com';

  if (!apiKey || !senderEmail) {
    console.error('Config manquante : BREVO_API_KEY ou BREVO_SENDER_EMAIL');
    return { statusCode: 500, body: JSON.stringify({ error: 'Configuration serveur incomplète' }) };
  }

  // ── Build file summary for email ──
  let fileSummary = '<ul>';
  if (files.length > 0) {
    files.forEach(f => {
      fileSummary += `<li>📄 ${escapeHtml(f.filename)} — ${(f.size / 1024).toFixed(0)} ko</li>`;
    });
  } else {
    fileSummary += '<li>Aucun fichier joint au formulaire</li>';
  }
  fileSummary += '</ul>';

  const htmlContent = `
    <h2>🛡 Nouvelle commande BailSafe</h2>
    <p><strong>Formule :</strong> ${escapeHtml(formule || 'Non précisée')} — ${montant} €</p>
    <p><strong>Nom :</strong> ${escapeHtml(name)}</p>
    <p><strong>Email :</strong> ${escapeHtml(email)}</p>
    <p><strong>Téléphone :</strong> ${escapeHtml(phone || 'Non renseigné')}</p>
    <p><strong>Document principal :</strong> ${escapeHtml(document_type)}</p>
    <p><strong>Message :</strong> ${escapeHtml(message || 'Aucune précision')}</p>
    <h3>Fichiers joints (${files.length})</h3>
    ${fileSummary}
    <hr>
    <p><small>✅ Consentement RGPD : ${escapeHtml(gdpr_consent || '')}</small></p>
    <p><small>✅ Candidat informé (art. 14) : ${escapeHtml(gdpr_candidat_informe || '')}</small></p>
    <p><small>✅ Renonciation rétractation : ${escapeHtml(retractation_renoncement || '')}</small></p>
  `;

  const sendBrevo = (payload) =>
    fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': apiKey, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(payload)
    });

  try {
    // Email notification Nolan
    const res = await sendBrevo({
      sender: { name: senderName, email: senderEmail },
      to: [{ email: notifEmail }],
      replyTo: { email, name },
      subject: `🛡 Nouvelle commande BailSafe — ${name} (${montant} €)`,
      htmlContent
    });
    if (!res.ok) {
      const errText = await res.text();
      console.error('Erreur Brevo (notification):', res.status, errText);
      return { statusCode: 502, body: JSON.stringify({ error: 'Envoi impossible' }) };
    }

    // Email confirmation client (non bloquant)
    try {
      const paypalUrl = montant === 69 ? 'https://paypal.me/NolanBunet/69EUR'
                      : montant === 149 ? 'https://paypal.me/NolanBunet/149EUR'
                      : 'https://paypal.me/NolanBunet/299EUR';
      await sendBrevo({
        sender: { name: senderName, email: senderEmail },
        to: [{ email, name }],
        subject: '✅ Votre commande BailSafe — en attente de paiement',
        htmlContent: `
          <h2>Merci ${escapeHtml(name)} !</h2>
          <p>Votre commande <strong>${escapeHtml(formule || 'Essentiel')}</strong> a bien été enregistrée.</p>
          <p><strong>Montant à régler :</strong> ${montant} €</p>
          <p><strong>Documents reçus :</strong> ${files.length} fichier(s)</p>
          <div style="background:#FFF8E1;border:1px solid #F59E0B;border-radius:8px;padding:16px;margin:16px 0">
            <p style="margin:0 0 8px"><strong>⚠ Paiement en attente</strong></p>
            <p style="margin:0 0 12px;font-size:14px">Votre analyse débutera dès réception du paiement.</p>
            <a href="${paypalUrl}" style="display:inline-block;background:#0070BA;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:700">🅿 Payer ${montant} € avec PayPal</a>
            <p style="font-size:12px;color:#666;margin-top:8px">Carte bancaire acceptée — pas besoin de compte PayPal</p>
          </div>
          <h3>Prochaines étapes</h3>
          <ol>
            <li>Payez via le bouton PayPal ci-dessus</li>
            <li>Nous confirmons le paiement et lançons l'analyse forensique</li>
            <li>Vous recevez votre rapport PDF sous <strong>24h</strong> à cette adresse</li>
          </ol>
          <p>Besoin d'aide ? Répondez à cet email ou contactez <a href="mailto:contact.bailsafe@gmail.com">contact.bailsafe@gmail.com</a>.</p>
          <hr>
          <p style="color:#6B6152;font-size:12px">BailSafe — Audit anti-fraude documentaire</p>
        `
      });
    } catch (e) {
      console.error('Erreur confirmation client:', e);
    }

    return {
      statusCode: 200,
      headers: { 'Access-Control-Allow-Origin': 'https://bail-safe.netlify.app' },
      body: JSON.stringify({ ok: true, files: files.length })
    };
  } catch (err) {
    console.error('Erreur fonction order:', err);
    return { statusCode: 500, body: JSON.stringify({ error: 'Erreur serveur' }) };
  }
};

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
