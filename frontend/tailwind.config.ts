import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#17211c",
        paper: "#f7f8f5",
        line: "#d9dfd4",
        risk: "#b3261e",
        cobalt: "#275dad",
        signal: "#e3a008",
        good: "#1a7f4b"
      }
    }
  },
  plugins: []
};

export default config;

