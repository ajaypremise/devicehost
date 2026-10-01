import PublicDownloadForm from "./PublicDownloadForm";

export const metadata = { title: "Download WindowsProtect", description: "Prepare WindowsProtect for your PC" };

export default function DownloadPage() {
  return <main className="downloadPage"><section className="downloadCard">
    <div className="downloadBrand">WINDOWSPROTECT</div>
    <h1>Protect this PC</h1>
    <p className="downloadIntro">Enter your details and download your personal WindowsProtect installer. Open this page on the Windows PC you want to protect.</p>
    <PublicDownloadForm />
    <p className="downloadPrivacy">Your contact details are saved securely in the support dashboard when this PC is enrolled; they are not placed inside the installer files. The setup authorization expires after four hours and works once.</p>
  </section></main>;
}
