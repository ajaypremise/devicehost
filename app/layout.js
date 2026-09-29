import "./globals.css";

export const metadata = {
  title: "DeviceHost",
  description: "WindowsProtect device dashboard",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
