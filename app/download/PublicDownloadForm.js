"use client";
import { useState } from "react";

export default function PublicDownloadForm() {
  const [busy,setBusy]=useState(false),[error,setError]=useState(""),[done,setDone]=useState(false);
  async function submit(event) {
    event.preventDefault();setBusy(true);setError("");setDone(false);
    const form=new FormData(event.currentTarget);
    try {
      const response=await fetch("/api/public/installer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(Object.fromEntries(form))});
      if(!response.ok){const data=await response.json();throw new Error(data.error || "Unable to prepare download.");}
      const blob=await response.blob(),url=URL.createObjectURL(blob);
      const match=/filename="([^"]+)"/.exec(response.headers.get("content-disposition") || "");
      const link=document.createElement("a");link.href=url;link.download=match?.[1] || "WindowsProtect_Setup.zip";document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);setDone(true);
    } catch (problem) { setError(problem.message || "Unable to prepare download."); }
    finally { setBusy(false); }
  }
  return <form className="publicDownloadForm" onSubmit={submit}>
    <label>Full name<input name="name" autoComplete="name" maxLength={80} required /></label>
    <label>Phone number<input name="phone" type="tel" autoComplete="tel" inputMode="tel" maxLength={40} placeholder="Include country code" required /></label>
    <label>Email address<input name="email" type="email" autoComplete="email" maxLength={254} required /></label>
    <label>PC name <span className="optionalLabel">(optional)</span><input name="pc_name" maxLength={80} placeholder="e.g. Home laptop" /></label>
    <input className="downloadTrap" name="website" tabIndex={-1} autoComplete="off" aria-hidden="true" />
    <button disabled={busy} type="submit">{busy ? "Preparing your download…" : "Download WindowsProtect"}</button>
    {error && <div className="downloadError" role="alert">{error}</div>}
    {done && <div className="downloadSuccess" role="status"><strong>Your download is ready.</strong><span>Open Downloads, extract the ZIP, then run WindowsProtect_Setup.exe. Keep both files together.</span></div>}
  </form>;
}
