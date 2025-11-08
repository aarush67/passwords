// script.js (complete)

// Toast
function toast(msg){
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.style.display = "block";
  setTimeout(()=> t.style.display = "none", 2000);
}

// Secure random integer in [0, n)
function secureRandInt(n){
  const max = Math.floor(0xFFFFFFFF / n) * n;
  const arr = new Uint32Array(1);
  while (true){
    crypto.getRandomValues(arr);
    if (arr[0] < max) return arr[0] % n;
  }
}

// Character password generator
function generateChars(len){
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?";
  let out = "";
  for (let i=0; i<len; i++){
    out += charset[ secureRandInt(charset.length) ];
  }
  return out;
}

// Passphrase generator using WORDS array
function generatePassphrase(wordsCount){
  if (!Array.isArray(WORDS) || WORDS.length === 0) return "wordlist missing";
  const out = [];
  // clamp wordsCount to a reasonable range
  const wc = Math.max(2, Math.min(12, Math.floor(wordsCount)));
  for (let i=0;i<wc;i++){
    out.push( WORDS[ secureRandInt(WORDS.length) ] );
  }
  return out.join(" ");
}

// SHA-1 hex (uppercase) used for HIBP k-anonymity
async function sha1Hex(msg){
  const buf = new TextEncoder().encode(msg);
  const hash = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
}

// HIBP k-anonymity check
async function checkPwned(password){
  try{
    const sha1 = await sha1Hex(password);
    const prefix = sha1.slice(0,5);
    const suffix = sha1.slice(5);
    const res = await fetch('https://api.pwnedpasswords.com/range/' + prefix);
    if (!res.ok) return 0;
    const text = await res.text();
    const lines = text.split('\n');
    for (const line of lines){
      const [s,count] = line.trim().split(':');
      if (s === suffix) return parseInt(count,10);
    }
    return 0;
  }catch(e){
    console.warn("HIBP check failed:", e);
    return 0;
  }
}

// UI elements
const modeEl = document.getElementById("mode");
const lenEl = document.getElementById("length");
const generateBtn = document.getElementById("generate");
const copyBtn = document.getElementById("copy");
const pwEl = document.getElementById("pw");
const strengthBar = document.getElementById("strengthBar");
const strengthText = document.getElementById("strengthText");
const pwnedInfo = document.getElementById("pwnedInfo");
const exportBtn = document.getElementById("exportBtn");

const checkInput = document.getElementById("checkInput");
const checkBtn = document.getElementById("checkBtn");
const copyCheckBtn = document.getElementById("copyCheckBtn");
const checkPw = document.getElementById("checkPw");
const checkStrengthBar = document.getElementById("checkStrengthBar");
const checkStrengthText = document.getElementById("checkStrengthText");
const checkPwnedInfo = document.getElementById("checkPwnedInfo");
const suggestion = document.getElementById("suggestion");

const modeToggle = document.getElementById("modeToggle");

// copy helper - copies visible text content (real password as it's stored)
async function copyText(el){
  const txt = el.textContent;
  if (!txt) return;
  await navigator.clipboard.writeText(txt);
  toast("Copied to clipboard");
}

// generate and show password (handles both modes)
async function generateAndShow(){
  const mode = modeEl.value;
  const rawLen = parseInt(lenEl.value) || 16;

  let out;
  if (mode === 'passphrase') {
    // treat length input as number of words for passphrase
    const wordsCount = Math.max(2, Math.min(12, Math.floor(rawLen)));
    out = generatePassphrase(wordsCount);
  } else {
    // characters mode: treat length as characters
    const charsLen = Math.max(4, Math.min(128, Math.floor(rawLen)));
    out = generateChars(charsLen);
  }

  pwEl.textContent = out;

  // strength using zxcvbn if available
  try {
    const z = zxcvbn(out);
    const score = z.score;
    strengthBar.style.width = ((score/4)*100) + '%';
    const labels = ['Very weak','Weak','So-so','Good','Excellent'];
    strengthText.textContent = `Strength: ${labels[score]} • ${Math.round(z.entropy)} bits`;
  } catch(e) {
    strengthBar.style.width = '0%';
    strengthText.textContent = 'Strength: —';
  }

  // HIBP check (client-side, safe)
  pwnedInfo.textContent = 'Checking breaches…';
  const count = await checkPwned(out);
  if (count > 0) pwnedInfo.innerHTML = `<svg class="warn" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg"><circle cx="9" cy="9" r="9"/></svg> Appeared in breaches ${count}`;
  else pwnedInfo.innerHTML = `<svg class="check" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg"><circle cx="9" cy="9" r="9"/></svg> Not found in HIBP`;
}

// wire up generate / copy / export
generateBtn.addEventListener("click", generateAndShow);
pwEl.addEventListener("click", ()=> copyText(pwEl));
copyBtn.addEventListener("click", ()=> copyText(pwEl));

exportBtn.addEventListener("click", ()=>{
  const password = pwEl.textContent;
  if (!password) return alert("Generate a password first!");
  const csvContent = `name,username,password,uri,notes,favorite\nGenerated Password,,${password},,,false`;
  const blob = new Blob([csvContent], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "generated-password.csv";
  a.click();
  URL.revokeObjectURL(url);
  toast("CSV downloaded");
});

// check user-entered password
async function checkPassword(){
  const pw = checkInput.value;
  if (!pw) return alert("Enter a password to check");

  checkPw.textContent = pw;

  try {
    const z = zxcvbn(pw);
    const score = z.score;
    checkStrengthBar.style.width = ((score/4)*100) + '%';
    const labels = ['Very weak','Weak','So-so','Good','Excellent'];
    checkStrengthText.textContent = `Strength: ${labels[score]} • ${Math.round(z.entropy)} bits`;
    suggestion.textContent = z.feedback.warning || (z.feedback.suggestions || []).join(' ') || '';
  } catch(e) {
    checkStrengthBar.style.width = '0%';
    checkStrengthText.textContent = 'Strength: —';
    suggestion.textContent = '';
  }

  checkPwnedInfo.textContent = 'Checking breaches…';
  const count = await checkPwned(pw);
  if (count > 0) checkPwnedInfo.innerHTML = `<svg class="warn" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg"><circle cx="9" cy="9" r="9"/></svg> Appeared in breaches ${count}`;
  else checkPwnedInfo.innerHTML = `<svg class="check" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg"><circle cx="9" cy="9" r="9"/></svg> Not found in HIBP`;
}

checkBtn.addEventListener("click", checkPassword);
checkPw.addEventListener("click", ()=> copyText(checkPw));
copyCheckBtn.addEventListener("click", ()=> copyText(checkPw));

// tabs
document.querySelectorAll(".tab-btn").forEach(btn=>{
  btn.addEventListener("click", ()=>{
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    document.getElementById("generate-tab").style.display = tab === "generate" ? "block" : "none";
    document.getElementById("check-tab").style.display = tab === "check" ? "block" : "none";
  });
});

// dark/light toggle
modeToggle.addEventListener("click", ()=>{
  document.body.classList.toggle("dark");
  modeToggle.textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
});

// generate an initial password
generateAndShow();
