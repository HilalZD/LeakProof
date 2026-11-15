import posthog from "posthog-js";

// Rule 2: PostHog starts tracking as soon as the app loads
posthog.init("phc_test_key", { api_host: "https://us.i.posthog.com" });

export default posthog;
