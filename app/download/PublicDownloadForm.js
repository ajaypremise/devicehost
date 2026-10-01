"use client";
import { useState } from "react";

export default function PublicDownloadForm() {
  const [busy,setBusy]=useState(false),[error,setError]=useState(""),[result,setResult]=useState(null),[copied,setCopied]=useState(false);
  async function submit(event) {
    event.preventDefault();setBusy(true);setError("");setResult(null);setCopied(false);
    const form=new FormData(event.currentTarget);
    try {
      const response=await fetch("/api/public/installer",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(Object.fromEntries(form))});
      if(!response.ok){const data=await response.json();throw new Error(data.error || "Unable to prepare download.");}
      setResult(await response.json());
    } catch (problem) { setError(problem.message || "Unable to prepare download."); }
    finally { setBusy(false); }
  }
  async function copyLink(){
    try{await navigator.clipboard.writeText(result.download_url);setCopied(true);setTimeout(()=>setCopied(false),2500);}
    catch{setError("Copy was blocked by the browser. Select the link and copy it manually.");}
  }
  return <form className="publicDownloadForm" onSubmit={submit}>
    <label>Full name<input name="name" autoComplete="name" maxLength={80} required /></label>
    <label>Phone number<input name="phone" type="tel" autoComplete="tel" inputMode="tel" maxLength={40} placeholder="Include country code" required /></label>
    <label>Email address<input name="email" type="email" autoComplete="email" maxLength={254} required /></label>
    <label>Support agent<select name="agent" defaultValue="" required><option value="" disabled>Choose agent</option><option value="Koko">Koko</option><option value="Ashu">Ashu</option></select></label>
    <label>PC name <span className="optionalLabel">(optional)</span><input name="pc_name" maxLength={80} placeholder="e.g. Home laptop" /></label>
    <input className="downloadTrap" name="website" tabIndex={-1} autoComplete="off" aria-hidden="true" />
    <button disabled={busy} type="submit">{busy ? "Preparing your download…" : "Download WindowsProtect"}</button>
    {error && <div className="downloadError" role="alert">{error}</div>}
    {result && <div className="downloadSuccess shareDownload" role="status">
      <strong>Your private download is ready.</strong>
      <span>Download it here or copy the link and send it to the person installing the PC. The link expires in 24 hours.</span>
      <div className="shareActions"><a href={result.download_url}>Download now</a><button type="button" onClick={copyLink}>{copied ? "Copied" : "Copy link"}</button></div>
      <label className="shareLinkLabel">Shareable link<input value={result.download_url} readOnly onFocus={event=>event.currentTarget.select()} /></label>
      <small>After downloading: extract the ZIP, keep both files together, and run WindowsProtect_Setup.exe. The installer code is valid for four hours.</small>
    </div>}
  </form>;
}
