import * as CookieConsent from "vanilla-cookieconsent";
import posthog from "posthog-js";

// ✅ Rule 2: analytics only start after the user says yes in the cookie banner
CookieConsent.run({
  categories: {
    necessary: { enabled: true, readOnly: true },
    analytics: {},
  },
  onConsent: () => {
    if (CookieConsent.acceptedCategory("analytics")) {
      loadGoogleAnalytics();
      posthog.init("phc_test_key", { api_host: "https://us.i.posthog.com" });
    }
  },
  language: {
    default: "en",
    translations: {
      en: {
        consentModal: {
          title: "We use cookies",
          description: "Analytics help us improve FitTrack. You can say no.",
          acceptAllBtn: "Accept",
          acceptNecessaryBtn: "Reject",
        },
      },
    },
  },
});

function loadGoogleAnalytics() {
  const script = document.createElement("script");
  script.src = "https://www.googletagmanager.com/gtag/js?id=G-TEST123";
  document.head.appendChild(script);
  window.dataLayer = window.dataLayer || [];
  function gtag() { window.dataLayer.push(arguments); }
  gtag("js", new Date());
  gtag("config", "G-TEST123");
}
