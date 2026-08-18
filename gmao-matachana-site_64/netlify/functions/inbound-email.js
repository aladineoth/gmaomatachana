// netlify/functions/inbound-email.js
//
// Reçoit les emails de demande d'intervention et crée directement l'intervention dans
// Firestore — elle apparaît ensuite dans le tableau de bord du bureau au prochain
// rafraîchissement, sans aucune action manuelle.
//
// Deux façons d'alimenter cette fonction, au choix (les deux peuvent cohabiter) :
//
//  A) Une adresse Gmail dédiée + un petit script Google (recommandé pour démarrer —
//     ne nécessite AUCUN accès au domaine matachana.fr ni à son DNS). Voir le fichier
//     apps-script-gmail-watcher.gs fourni à côté de celui-ci.
//
//  B) Mailgun, sur un sous-domaine dédié (ex. intervention.matachana.fr), si vous obtenez
//     un jour l'accès administrateur au DNS du domaine — plus robuste à grande échelle,
//     gère aussi les pièces jointes et les accusés de réception.
//
// Variables d'environnement à définir dans Netlify (Site settings → Environment variables) :
//   FIREBASE_SERVICE_ACCOUNT → le JSON complet du compte de service Firebase, en une seule ligne
//   INBOUND_SHARED_SECRET    → un mot de passe que vous inventez vous-même, à recopier dans le
//                              script Google (voie A) — protège contre les requêtes falsifiées.
//   MAILGUN_SIGNING_KEY      → uniquement nécessaire si vous utilisez la voie B (Mailgun).
//
// Déployez ce fichier sous netlify/functions/inbound-email.js à la racine de votre site Netlify.
// Netlify le publie automatiquement à l'adresse :
//   https://VOTRE-SITE.netlify.app/.netlify/functions/inbound-email

const crypto = require('crypto');
const busboy = require('busboy');
const admin = require('firebase-admin');

const FIRESTORE_COLLECTION = 'gmao_shared';
const STORAGE_KEY = 'gmao-matachana-state-v2';
const CORE_DOC_ID = `${STORAGE_KEY}__core`;

// ---------- initialisation Firebase Admin (une seule fois, réutilisée entre appels) ----------
let firestoreDb = null;
function getFirestore(){
  if(firestoreDb) return firestoreDb;
  if(!admin.apps.length){
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  }
  firestoreDb = admin.firestore();
  return firestoreDb;
}

// ---------- vérifie que la requête provient bien de Mailgun (voie B, anti-usurpation) ----------
function verifyMailgunSignature({ timestamp, token, signature }){
  const signingKey = process.env.MAILGUN_SIGNING_KEY;
  if(!signingKey) return false;
  const expected = crypto.createHmac('sha256', signingKey).update(timestamp + token).digest('hex');
  try{
    return crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(signature || '', 'utf8'));
  }catch(e){ return false; }
}

// ---------- vérifie le mot de passe partagé (voie A, Gmail + Google Apps Script) ----------
function verifySharedSecret(providedSecret){
  const expected = process.env.INBOUND_SHARED_SECRET;
  if(!expected) return false;
  try{
    return crypto.timingSafeEqual(Buffer.from(String(providedSecret||''), 'utf8'), Buffer.from(expected, 'utf8'));
  }catch(e){ return false; }
}

// ---------- extrait les champs multipart/form-data envoyés par Mailgun (voie B) ----------
function parseMultipartFields(event){
  return new Promise((resolve, reject)=>{
    const fields = {};
    const bb = busboy({ headers: { 'content-type': event.headers['content-type'] || event.headers['Content-Type'] } });
    bb.on('field', (name, val)=>{ fields[name] = val; });
    bb.on('file', (name, stream)=>{ stream.resume(); }); // pièces jointes ignorées pour l'instant
    bb.on('close', ()=> resolve(fields));
    bb.on('error', reject);
    bb.end(Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8'));
  });
}

// ---------- retrouve le numéro de série et la description dans le texte de l'email ----------
function extractSerial(text){
  const m = (text||'').match(/N[°o]\s*(?:de\s*)?s[ée]rie\s*:?\s*([A-Za-z0-9._-]+)/i);
  return m ? m[1].trim() : null;
}
function extractField(text, label){
  const re = new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*:\\s*(.+)', 'i');
  const m = (text||'').match(re);
  return m ? m[1].trim() : '';
}

// ---------- logique commune aux deux voies : crée l'intervention dans Firestore ----------
async function createInterventionFromEmail({ subject, bodyText, fromRaw }){
  const serial = extractSerial(bodyText) || extractSerial(subject);
  const description = extractField(bodyText, 'Description') || bodyText.slice(0, 500);

  if(!serial){
    console.warn('Aucun numéro de série détecté — intervention non créée.', { subject, from: fromRaw });
    return { created: false, reason: 'no_serial' };
  }

  const db = getFirestore();
  const docRef = db.collection(FIRESTORE_COLLECTION).doc(CORE_DOC_ID);
  const snap = await docRef.get();
  if(!snap.exists){
    console.error('Document Firestore introuvable — vérifiez FIRESTORE_COLLECTION / CORE_DOC_ID.');
    return { created: false, reason: 'state_not_found' };
  }

  const state = JSON.parse(snap.data().value);
  const machine = (state.machines||[]).find(m=>(m.serial||'').trim().toUpperCase() === serial.trim().toUpperCase());

  if(!machine){
    console.warn(`Numéro de série "${serial}" non reconnu dans le GMAO — intervention non créée.`);
    return { created: false, reason: 'serial_not_found', serial };
  }

  const newIntervention = {
    id: 'iv_' + crypto.randomBytes(6).toString('hex'),
    clientId: machine.clientId,
    machineId: machine.id,
    serial: machine.serial,
    panne: description || subject || 'Demande reçue par email — description à préciser',
    status: 'demande',
    type: null,
    priseEnCharge: null,
    piecesNecessaires: '',
    piecesListe: [],
    priorite: 'normale',
    notesBureau: `Créée automatiquement depuis un email reçu de ${fromRaw}.`,
    technicianId: null,
    plannedDate: null,
    plannedEndDate: null,
    numeroAppel: null,
    valide: false, valideeAt: null, valideePar: null,
    piecesCommandees: false, piecesCommandeesAt: null, piecesCommandeesPar: null,
    clientConfirmation: null, clientProposedDate: null, clientNote: null,
    createdAt: new Date().toISOString(),
    createdBy: 'email',
  };

  state.interventions = state.interventions || [];
  state.interventions.push(newIntervention);
  state.auditLog = state.auditLog || [];
  state.auditLog.push({
    action: 'intervention_created_by_email',
    detail: `${machine.serial} — depuis ${fromRaw}`,
    at: new Date().toISOString(),
  });

  await docRef.set({ value: JSON.stringify(state), updatedAt: Date.now() });
  console.log(`Intervention créée depuis un email pour la machine ${machine.serial}.`);
  return { created: true, serial: machine.serial };
}

exports.handler = async function(event){
  if(event.httpMethod !== 'POST'){
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const contentType = (event.headers['content-type'] || event.headers['Content-Type'] || '').toLowerCase();

  // ---------- Voie A : Gmail + Google Apps Script (JSON simple + mot de passe partagé) ----------
  if(contentType.includes('application/json')){
    let payload;
    try{ payload = JSON.parse(event.body); }
    catch(e){ return { statusCode: 400, body: 'Invalid JSON' }; }

    if(!verifySharedSecret(payload.secret)){
      console.warn('Mot de passe partagé invalide — requête rejetée.');
      return { statusCode: 401, body: 'Invalid secret' };
    }

    const result = await createInterventionFromEmail({
      subject: payload.subject || '',
      bodyText: payload.body || '',
      fromRaw: payload.from || '',
    });
    return { statusCode: 200, body: JSON.stringify(result) };
  }

  // ---------- Voie B : Mailgun (multipart/form-data + signature HMAC) ----------
  let fields;
  try{
    fields = await parseMultipartFields(event);
  }catch(e){
    console.error('Échec de lecture du contenu de l\u2019email', e);
    return { statusCode: 400, body: 'Bad request' };
  }

  if(!verifyMailgunSignature(fields)){
    console.warn('Signature Mailgun invalide — requête rejetée.');
    return { statusCode: 401, body: 'Invalid signature' };
  }

  const result = await createInterventionFromEmail({
    subject: fields.subject || '',
    bodyText: fields['body-plain'] || fields['stripped-text'] || '',
    fromRaw: fields.sender || fields.from || '',
  });
  return { statusCode: 200, body: JSON.stringify(result) };
};
