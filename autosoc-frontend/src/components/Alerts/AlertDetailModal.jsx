import { motion, AnimatePresence } from 'framer-motion';
import { 
  X, 
  Target, 
  MapPin, 
  AlertTriangle,
  FileText,
  Search,
  Lock
} from 'lucide-react';

const severityColors = {
  CRITICAL: 'text-red-500 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  LOW: 'text-green-500 bg-green-500/10 border-green-500/30',
};

const attackStages = [
  { stage: 'Reconnaissance', icon: '🔍', completed: true },
  { stage: 'Initial Access', icon: '🎣', completed: true },
  { stage: 'Execution', icon: '⚡', completed: true },
  { stage: 'C2', icon: '📡', completed: true },
  { stage: 'Impact', icon: '💥', completed: true },
];

export default function AlertDetailModal({ event, onClose }) {
  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto glass-card rounded-xl"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="sticky top-0 z-10 flex items-center justify-between p-6 border-b border-white/10 bg-cyber-card/95 backdrop-blur-md">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${severityColors[event.severity]}`}>
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-xl font-bold">{event.event_type.toUpperCase()}</h2>
                <p className="text-sm text-gray-500">Event ID: {event.id}</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/10 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 space-y-6">
            {/* Basic Info Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-3 rounded-lg bg-white/5">
                <div className="text-xs text-gray-500 mb-1">Rule Name</div>
                <div className="font-medium">{event.rule}</div>
              </div>
              <div className="p-3 rounded-lg bg-white/5">
                <div className="text-xs text-gray-500 mb-1">MITRE ATT&CK</div>
                <div className="font-mono text-cyan-400">{event.mitre_id}</div>
              </div>
              <div className="p-3 rounded-lg bg-white/5">
                <div className="text-xs text-gray-500 mb-1">Timestamp</div>
                <div className="font-mono text-sm">{new Date(event.timestamp).toLocaleString()}</div>
              </div>
              <div className="p-3 rounded-lg bg-white/5">
                <div className="text-xs text-gray-500 mb-1">Target</div>
                <div className="font-mono text-sm">{event.target_ip}</div>
              </div>
            </div>

            {/* Confidence Section */}
            <div className="p-4 rounded-lg bg-white/5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Confidence Score</span>
                <span className="text-2xl font-bold text-purple-400">{event.confidence_score}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <div 
                  className="h-2 rounded-full bg-gradient-to-r from-purple-500 to-cyan-500"
                  style={{ width: `${event.confidence_score}%` }}
                ></div>
              </div>
              <div className="flex justify-between mt-2 text-xs text-gray-500">
                <span>LOW</span>
                <span>MEDIUM</span>
                <span>HIGH</span>
                <span>CRITICAL</span>
              </div>
            </div>

            {/* Why is this malicious? */}
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30">
              <h3 className="font-semibold mb-2 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-500" />
                Why is this malicious?
              </h3>
              <ul className="space-y-2 text-sm text-gray-300">
                <li>• {event.reason}</li>
                <li>• Multiple threat intelligence sources confirm malicious activity</li>
                <li>• Pattern matches known attack behavior (MITRE {event.mitre_id})</li>
                <li>• Communication with known malicious infrastructure</li>
              </ul>
            </div>

            {/* Multi-Pillar Intelligence */}
            <div>
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <Target className="w-4 h-4" />
                Multi-Pillar Intelligence
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 rounded-lg bg-white/5">
                  <div className="text-xs text-gray-500 mb-1">🌐 IP Addresses</div>
                  <div className="space-y-1">
                    {event.iocs.ips.map((ip) => (
                      <div key={ip} className="font-mono text-sm">{ip}</div>
                    ))}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-white/5">
                  <div className="text-xs text-gray-500 mb-1">🌍 Domains</div>
                  <div className="space-y-1">
                    {event.iocs.domains.map((domain) => (
                      <div key={domain} className="font-mono text-sm text-cyan-400">{domain}</div>
                    ))}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-white/5">
                  <div className="text-xs text-gray-500 mb-1">🔗 URLs</div>
                  <div className="text-sm text-gray-400">{event.iocs.urls.length || 'None'}</div>
                </div>
                <div className="p-3 rounded-lg bg-white/5">
                  <div className="text-xs text-gray-500 mb-1">🧬 File Hashes</div>
                  <div className="text-sm text-gray-400">{event.iocs.hashes.length || 'None'}</div>
                </div>
              </div>
            </div>

            {/* Attack Chain */}
            <div>
              <h3 className="font-semibold mb-3">Attack Chain</h3>
              <div className="flex items-center justify-between">
                {attackStages.map((stage, idx) => (
                  <div key={stage.stage} className="flex-1 text-center relative">
                    <div className={`text-2xl mb-2 ${stage.completed ? 'opacity-100' : 'opacity-30'}`}>
                      {stage.icon}
                    </div>
                    <div className={`text-xs ${stage.completed ? 'text-gray-300' : 'text-gray-600'}`}>
                      {stage.stage}
                    </div>
                    {idx < attackStages.length - 1 && (
                      <div className="hidden md:block absolute w-1/2 h-px bg-gradient-to-r from-purple-500 to-transparent top-1/4 left-3/4"></div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Enrichment Data */}
            <div>
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <MapPin className="w-4 h-4" />
                Threat Intelligence Enrichment
              </h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="p-3 rounded-lg bg-white/5">
                  <div className="text-xs text-gray-500 mb-1">Country</div>
                  <div className="font-medium">{event.enrichment.country}</div>
                </div>
                <div className="p-3 rounded-lg bg-white/5">
                  <div className="text-xs text-gray-500 mb-1">ISP</div>
                  <div className="font-medium">{event.enrichment.isp}</div>
                </div>
                <div className="p-3 rounded-lg bg-white/5">
                  <div className="text-xs text-gray-500 mb-1">Reputation</div>
                  <div className="font-medium text-red-400">{event.enrichment.reputation}</div>
                </div>
              </div>
            </div>
          </div>

          {/* Actions Footer */}
          <div className="sticky bottom-0 flex justify-end gap-3 p-6 border-t border-white/10 bg-cyber-card/95 backdrop-blur-md">
            <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors">
              <Lock className="w-4 h-4" />
              Block IP
            </button>
            <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-500/20 text-purple-400 hover:bg-purple-500/30 transition-colors">
              <FileText className="w-4 h-4" />
              Create Case
            </button>
            <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 transition-colors">
              <Search className="w-4 h-4" />
              Investigate
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
