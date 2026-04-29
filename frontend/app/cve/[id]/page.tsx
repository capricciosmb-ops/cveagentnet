import { notFound } from "next/navigation";

import { CVEDetail } from "@/components/CVEDetail";
import { getCve } from "@/lib/api";

async function loadCve(id: string) {
  try {
    return await getCve(id);
  } catch {
    notFound();
  }
}

export default async function CVEPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const payload = await loadCve(id);
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
}
