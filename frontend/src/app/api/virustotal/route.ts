import { NextResponse } from "next/server";

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || "";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const hash = searchParams.get("hash");

  if (!hash) {
    return NextResponse.json({ error: "No hash provided" }, { status: 400 });
  }

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: {
        "x-apikey": VT_API_KEY,
      },
    });

    if (res.status === 404) {
      return NextResponse.json({ found: false }, { status: 404 });
    }

    if (!res.ok) {
      return NextResponse.json({ error: "VirusTotal API Error" }, { status: res.status });
    }

    const data = await res.json();
    const stats = data.data.attributes.last_analysis_stats;
    const permalink = `https://www.virustotal.com/gui/file/${hash}`;

    return NextResponse.json({
      found: true,
      stats: {
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected,
        harmless: stats.harmless,
      },
      permalink,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const formData = await request.formData();
    const file = formData.get("file") as Blob;

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    // Proxy the file upload to VirusTotal API
    const vtFormData = new FormData();
    vtFormData.append("file", file);

    const res = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
      },
      body: vtFormData,
    });

    if (!res.ok) {
      return NextResponse.json({ error: "Upload to VT failed" }, { status: res.status });
    }

    const data = await res.json();
    return NextResponse.json({
      success: true,
      id: data.data.id,
      message: "File successfully queued for analysis at VirusTotal",
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
