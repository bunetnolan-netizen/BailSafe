// Reçoit la commande du formulaire index.html et l'envoie par email via Brevo (UE, Paris).
// Clé API et email de notification lus depuis les variables d'environnement Netlify
// (Site configuration > Environment variables) — jamais commités dans le code.

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let data;
  try {
    data = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, body: JSON.stringify({ error: 'JSON invalide' }) };
  }

  const {
    name, email, phone, document_type, message,
    gdpr_consent, gdpr_candidat_informe, retractation_renoncement
  } = data;

  if (!name || !email || !document_type) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Champs requis manquants' }) };
  }

  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  const senderName = process.env.BREVO_SENDER_NAME || 'BailSafe';
  const notifEmail = process.env.BAILSAFE_NOTIF_EMAIL || 'bunetnolan@gmail.com';

  if (!apiKey || !senderEmail) {
    console.error('Configuration manquante : BREVO_API_KEY ou BREVO_SENDER_EMAIL');
    return { statusCode: 500, body: JSON.stringify({ error: 'Configuration serveur incomplète' }) };
  }

  const htmlContent = `
    <h2>Nouvelle commande BailSafe</h2>
    <p><strong>Nom :</strong> ${escapeHtml(name)}</p>
    <p><strong>Email :</strong> ${escapeHtml(email)}</p>
    <p><strong>Téléphone :</strong> ${escapeHtml(phone || 'Non renseigné')}</p>
    <p><strong>Type de document :</strong> ${escapeHtml(document_type)}</p>
    <p><strong>Message :</strong> ${escapeHtml(message || 'Aucune précision')}</p>
    <p><strong>Consentement RGPD :</strong> ${escapeHtml(gdpr_consent || '')}</p>
    <p><strong>Candidat informé (art. 14) :</strong> ${escapeHtml(gdpr_candidat_informe || '')}</p>
    <p><strong>Renonciation rétractation :</strong> ${escapeHtml(retractation_renoncement || '')}</p>
  `;

  try {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'Content-Type': 'application/json',
        Accept: 'application/json'
      },
      body: JSON.stringify({
        sender: { name: senderName, email: senderEmail },
        to: [{ email: notifEmail }],
        replyTo: { email, name },
        subject: `Nouvelle commande BailSafe — ${name}`,
        htmlContent
      })
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error('Erreur Brevo:', res.status, errText);
      return { statusCode: 502, body: JSON.stringify({ error: 'Envoi impossible' }) };
    }

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    console.error('Erreur fonction order:', err);
    return { statusCode: 500, body: JSON.stringify({ error: 'Erreur serveur' }) };
  }
};

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
