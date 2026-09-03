import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Shield, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import clsx from 'clsx'
import api from '../api'
import { PageHeader, Card, Spinner, OutputBlock } from '../components/UI'
import { CopyButton, SeverityBadge } from '../features/common/badges'
import type { Top10ListItem, Top10ListResponse, Top10Detail } from '../types'

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <div><h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">{title}</h4>{children}</div>
}

export default function Top10() {
  const [selectedRank, setSelectedRank] = useState<number | null>(null)
  const [expandedTech, setExpandedTech] = useState<number | null>(null)

  const { data: listData, isLoading } = useQuery({
    queryKey: ['top10'],
    queryFn: async () => { const res = await api.get<Top10ListResponse>('/top10'); return res.data.vulns },
  })

  const { data: detailData } = useQuery({
    queryKey: ['top10-detail', selectedRank],
    queryFn: async () => { const res = await api.get<Top10Detail>(`/top10/${selectedRank}`); return res.data },
    enabled: selectedRank !== null,
  })

  const vulns: Top10ListItem[] = listData || []
  const detail: Top10Detail | null = detailData || null

  if (isLoading) return <Spinner text="Loading Top 10..." color="purple" />

  return (
    <div className="space-y-4 sm:space-y-6">
      <PageHeader title="OWASP Top 10" subtitle="Web application security vulnerabilities reference guide" icon={<Shield className="w-8 h-8" />} color="purple" />

      <div className="space-y-2">
        {vulns.map((v) => (
          <div key={v.rank}>
            <button
              onClick={() => setSelectedRank(selectedRank === v.rank ? null : v.rank)}
              className={clsx(
                'w-full text-left p-3 sm:p-4 bg-gray-900 border rounded-xl transition-all',
                selectedRank === v.rank ? 'border-webforge-600' : 'border-gray-800/40 hover:border-gray-700/50',
              )}
            >
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-gray-800 flex items-center justify-center font-bold text-lg text-webforge-400 shrink-0">{v.rank}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-gray-500">{v.owasp_id}</span>
                    <span className="font-medium text-sm text-gray-100">{v.name}</span>
                    <SeverityBadge severity={v.severity} variant="soft" />
                    <span className="text-xs text-gray-500 hidden sm:inline">CVSS {v.cvss_range}</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1 line-clamp-1">{v.description}</p>
                </div>
                <div className="text-xs text-gray-500 hidden sm:block">{v.techniques_count || 0} techniques</div>
                {selectedRank === v.rank ? <ChevronDown className="w-5 h-5 text-gray-500 shrink-0" /> : <ChevronRight className="w-5 h-5 text-gray-500 shrink-0" />}
              </div>
            </button>

            {selectedRank === v.rank && detail && (
              <div className="mt-2 ml-3 sm:ml-14 space-y-4 border-l-2 border-gray-800 pl-3 sm:pl-6 pb-2">
                <Section title="Description"><p className="text-sm text-gray-300">{detail.description}</p></Section>
                <Section title="How It Works"><OutputBlock maxHeight="max-h-none">{detail.how_it_works}</OutputBlock></Section>
                <Section title="Impact"><p className="text-sm text-gray-300">{detail.impact}</p></Section>

                {detail.techniques.length > 0 && (
                  <Section title="Exploitation Techniques">
                    <div className="space-y-2">
                      {detail.techniques.map((tech, i) => (
                        <div key={i} className="bg-gray-950/50 border border-gray-800 rounded-lg overflow-hidden">
                          <button onClick={() => setExpandedTech(expandedTech === i ? null : i)} className="w-full text-left p-3 flex items-center gap-2 hover:bg-gray-800/30 transition-colors">
                            <span className="text-yellow-400 font-mono text-sm shrink-0">{i + 1}.</span>
                            <span className="font-medium text-sm text-gray-200 truncate">{tech.name}</span>
                            <span className="text-xs text-gray-500 ml-auto hidden sm:inline">{tech.tools?.slice(0, 3).join(', ')}</span>
                            {expandedTech === i ? <ChevronDown className="w-4 h-4 text-gray-500 shrink-0" /> : <ChevronRight className="w-4 h-4 text-gray-500 shrink-0" />}
                          </button>
                          {expandedTech === i && (
                            <div className="px-3 pb-3 space-y-3 border-t border-gray-800">
                              <p className="text-sm text-gray-400 mt-2">{tech.description}</p>
                              {tech.payloads.length > 0 && (
                                <div>
                                  <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Payloads:</div>
                                  <div className="bg-gray-950 rounded p-3 space-y-1">
                                    {tech.payloads.map((p, j) => (
                                      <div key={j} className="flex items-center gap-2 group">
                                        <span className="text-red-400 shrink-0">&rarr;</span>
                                        <code className="text-xs text-gray-300 font-mono break-all flex-1">{p}</code>
                                        <CopyButton text={p} />
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {tech.detection_patterns.length > 0 && (
                                <div>
                                  <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Detection:</div>
                                  <div className="flex flex-wrap gap-1">
                                    {tech.detection_patterns.map((d, j) => (<span key={j} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{d}</span>))}
                                  </div>
                                </div>
                              )}
                              {tech.references?.length > 0 && (
                                <div className="flex gap-2 flex-wrap">
                                  {tech.references.map((ref, j) => (
                                    <a key={j} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-webforge-400 hover:text-webforge-300 px-2 py-1.5 min-h-[44px] flex items-center gap-1">Reference <ExternalLink className="w-3 h-3" /></a>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </Section>
                )}

                <Section title="Remediation">
                  <div className="space-y-1">
                    {detail.remediation.map((r, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm"><span className="text-webforge-400 mt-0.5 shrink-0">&check;</span><span className="text-gray-300">{r}</span></div>
                    ))}
                  </div>
                </Section>

                {detail.real_world_cves.length > 0 && (
                  <Section title="Real-World CVEs">
                    <div className="flex flex-wrap gap-2">
                      {detail.real_world_cves.map((cve, i) => (
                        <a key={i} href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer" className="text-xs bg-red-400/10 text-red-400 px-2.5 py-2 min-h-[44px] rounded font-mono flex items-center gap-1 hover:bg-red-400/20">{cve} <ExternalLink className="w-3 h-3" /></a>
                      ))}
                    </div>
                  </Section>
                )}

                {detail.tools.length > 0 && (
                  <Section title="Tools">
                    <div className="flex flex-wrap gap-2">
                      {detail.tools.map((tool, i) => (<span key={i} className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">{tool}</span>))}
                    </div>
                  </Section>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
