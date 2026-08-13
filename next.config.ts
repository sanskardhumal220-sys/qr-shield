import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: "/app",
        destination: "/app/index.html",
      },
    ];
  },
};

export default nextConfig;
