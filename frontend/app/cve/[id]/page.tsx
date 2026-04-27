import { notFound } from "next/navigation";

import { CVEDetail } from "@/components/CVEDetail";
import { getCve } from "@/lib/api";

export default async function CVEPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  try {
    const payload = await getCve(id);
    const jsonLd = {
      "@context": "https://cveagentnet.local/schema/jsonld_context.json",
      "@type": "Vulnerability",
      ...payload.cve,
      url: payload.cve.ui_url,
      sameAs: payload.cve.api_url,
    };
    return (
      <>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }}
        />
        <CVEDetail payload={payload} />
      </>
    );
  } catch {
    notFound();
  }
}
