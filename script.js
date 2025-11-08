// Toast
function toast(msg){
  const t=document.getElementById("toast");
  t.textContent=msg;
  t.style.display="block";
  setTimeout(()=>t.style.display="none",2000);
}

// Secure random integer
function secureRandInt(n){
  const max=Math.floor(0xFFFFFFFF/n)*n;
  const arr=new Uint32Array(1);
  while(true){
    crypto.getRandomValues(arr);
    if(arr[0]<max) return arr[0]%n;
  }
}

// Random character password
function generateChars(len){
  const charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?";
  let out="";
  for(let i=0;i<len;i++){ out+=charset[secureRandInt(charset.length)]; }
  return out;
}

// Passphrase
function generatePassphrase(wordsCount){
  let out=[];
  for(let i=0;i<wordsCount;i++){
    out.push(WORDS[secureRandInt(WORDS.length)]);
  }
  return out.join(" ");
}

// SHA1 Hex
async function sha1Hex(msg){
  const buf=new TextEncoder().encode(msg);
  const hash=await crypto.subtle.digest("SHA-1",buf);
  return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
}

// HIBP check
async function checkPwned(password){
  try{
    const sha1=await sha1Hex(password);
    const prefix=sha1.slice(0,5), suffix=sha1.slice(5);
    const res=await fetch('https://api.pwnedpasswords.com/range/'+prefix);
    if(!res.ok) return 0;
    const lines=(await res.text()).split('\n');
    for(const line of lines){
      const [s,count]=line.trim().split(":");
      if(s===suffix) return parseInt(count,10);
    }
    return 0;
  }catch(e){ console.warn(e); return 0; }
}

// UI elements
const modeEl=document.getElementById("mode");
const lenEl=document.getElementById("length");
const generateBtn=document.getElementById("generate");
const copyBtn=document.getElementById("copy");
const pwEl=document.getElementById("pw");
const strengthBar=document.getElementById("strengthBar");
const strengthText=document.getElementById("strengthText");
const pwnedInfo=document.getElementById("pwnedInfo");
const exportBtn=document.getElementById("exportBtn");

// Generate password
async function generateAndShow(){
  const mode=modeEl.value;
  const len=parseInt(lenEl.value)||16;
  const out=mode==="chars"?generateChars(len):generatePassphrase(Math.max(3,Math.min(8,Math.round(len/4))));
  pwEl.textContent=out;

  // Strength meter
  try{
    const z=zxcvbn(out);
    const score=z.score;
    strengthBar.style.width=((score/4)*100)+'%';
    const labels=['Very weak','Weak','So-so','Good','Excellent'];
    strengthText.textContent=`Strength: ${labels[score]} • ${Math.round(z.entropy)} bits entropy`;
  }catch(e){
    strengthBar.style.width='0%';
    strengthText.textContent='Strength: —';
  }

  // HIBP check
  pwnedInfo.textContent="Checking breaches…";
  const count=await checkPwned(out);
  pwnedInfo.textContent=count>0?`⚠️ Appeared in breaches ${count}`:"✅ Not found in HIBP";
}

generateBtn.addEventListener("click", generateAndShow);

// Copy to clipboard
copyBtn.addEventListener("click", async ()=>{
  const txt=pwEl.textContent;
  if(!txt||txt==="—") return;
  await navigator.clipboard.writeText(txt);
  toast("Copied — clears in 15s");
  setTimeout(()=>{
    pwEl.textContent='—';
    strengthBar.style.width='0%';
    strengthText.textContent='Strength: —';
    pwnedInfo.textContent='';
  },15000);
});

// Export to Bitwarden CSV
exportBtn.addEventListener("click", ()=>{
  const password=pwEl.textContent;
  if(!password||password==="—") return alert("Generate a password first!");

  const csvContent=`name,username,password,uri,notes,favorite\nGenerated Password,,${password},,,false`;
  const blob=new Blob([csvContent], {type:"text/csv"});
  const url=URL.createObjectURL(blob);

  const a=document.createElement("a");
  a.href=url;
  a.download="generated-password.csv";
  a.click();
  URL.revokeObjectURL(url);
  toast("CSV downloaded for Bitwarden import");
});

// Keyboard shortcuts
document.addEventListener("keydown",(e)=>{
  if(e.key==='g'||e.key==='G'){ generateAndShow(); e.preventDefault(); }
  if(e.key==='c'||e.key==='C'){ copyBtn.click(); e.preventDefault(); }
});

// Initial generate
generateAndShow();
