import PublicDownloadForm from "./PublicDownloadForm";

export const metadata = { title: "Download WindowsProtect", description: "Prepare WindowsProtect for your PC" };

export default function DownloadPage() {
  return <main className="downloadPage"><section className="downloadCard">
    <div className="downloadBrand">WINDOWSPROTECT</div>
    <h1>Protect this PC</h1>
    <p className="downloadIntro">Enter your details and download your personal WindowsProtect installer. Open this page on the Windows PC you want to protect.</p>
    <PublicDownloadForm />
    <p className="downloadPrivacy">Your contact details are validated to protect this download service. They are not included in the installer. The installer authorization expires after 30 minutes and works once.</p>
  </section></main>;
}
