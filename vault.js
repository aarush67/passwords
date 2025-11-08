let vault = [];
let masterKey;

async function deriveKey(masterPass){
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(masterPass), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt: enc.encode("salt123"), iterations:250000, hash:"SHA-256"},
    keyMaterial,
    { name:"AES-GCM", length:256 },
    false,
    ["encrypt","decrypt"]
  );
}

async function encryptVault(vaultObj, key){
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(JSON.stringify(vaultObj));
  const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, data);
  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv,0);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

async function decryptVault(encoded, key){
  const combined = Uint8Array.from(atob(encoded), c=>c.charCodeAt(0));
  const iv = combined.slice(0,12);
  const ciphertext = combined.slice(12);
  const decrypted = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(decrypted));
}

// Vault UI
async function unlockVaultUI(){
  const masterPass = document.getElementById("masterPass").value;
  masterKey = await deriveKey(masterPass);
  const stored = localStorage.getItem("vault");
  if(stored){
    try { vault = await decryptVault(stored, masterKey); } 
    catch(e){ vault=[]; alert("Wrong master password or corrupted vault"); }
  } else vault=[];
  document.getElementById("vaultContent").style.display="block";
  renderVault();
}

async function addToVault(password){
  const count = await checkPwned(password);
  vault.push({password, breached: count});
  const enc = await encryptVault(vault, masterKey);
  localStorage.setItem("vault", enc);
  renderVault();
}

function renderVault(){
  const div = document.getElementById("vaultList");
  if(vault.length===0){ div.innerHTML="<i>Vault empty</i>"; return; }
  div.innerHTML="";
  vault.forEach((e,i)=>{
    const row = document.createElement("div");
    row.style.display="flex"; row.style.justifyContent="space-between"; row.style.padding="4px 0";
    const pass = document.createElement("span"); pass.textContent="••••••••";
    const status = document.createElement("span"); status.textContent=e.breached>0 ? `⚠️ Breached ${e.breached}`:"✅ Safe";
    row.append(pass,status);
    div.append(row);
  });
}

// Tabs
document.querySelectorAll(".tab-btn").forEach(btn=>{
  btn.addEventListener("click",()=>{
    document.querySelectorAll(".tab-btn").forEach(b=>b.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    document.getElementById("generate-tab").style.display=tab==="generate"?"block":"none";
    document.getElementById("vault-tab").style.display=tab==="vault"?"block":"none";
  });
});

document.getElementById("unlockVault").addEventListener("click", unlockVaultUI);
document.getElementById("checkAdd").addEventListener("click", async ()=>{
  const pw = document.getElementById("vaultPassword").value;
  if(!pw) return alert("Enter a password");
  await addToVault(pw);
  document.getElementById("vaultPassword").value="";
});
