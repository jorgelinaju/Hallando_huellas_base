// pages/_app.js
import { SpeedInsights } from "@vercel/speed-insights/next";
import '../styles/globals.css'; // Importa tus estilos

function MyApp({ Component, pageProps }) {
  return (
    <>
      <SpeedInsights />
      <Component {...pageProps} />
    </>
  );
}

export default MyApp;
