import { useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';
import CytoscapeComponent from 'react-cytoscapejs';

export default function CorrelationGraph({ campaign, onClose }) {
  const cyRef = useRef(null);

  // Build graph elements from campaign IOCs
  const elements = [
    // Nodes
    ...campaign.iocs.ips.map((ip) => ({
      data: { id: ip, label: ip, type: 'ip' },
      classes: 'ip-node'
    })),
    ...campaign.iocs.domains.map((domain) => ({
      data: { id: domain, label: domain, type: 'domain' },
      classes: 'domain-node'
    })),
    // Edges - connect IPs to domains
    ...campaign.iocs.ips.slice(0, 3).map((ip, idx) => ({
      data: { 
        id: `edge-${idx}`, 
        source: ip, 
        target: campaign.iocs.domains[0] || campaign.iocs.ips[1],
        label: 'resolves_to'
      }
    })),
  ];

  const layout = {
    name: 'cose',
    idealEdgeLength: 100,
    nodeOverlap: 20,
    refresh: 20,
    fit: true,
    padding: 30,
    randomize: false,
    componentSpacing: 100,
    nodeRepulsion: 400000,
    edgeElasticity: 100,
    nestingFactor: 5,
    gravity: 80,
    numIter: 1000,
    initialTemp: 200,
    coolingFactor: 0.95,
    minTemp: 1.0,
  };

  const stylesheet = [
    {
      selector: 'node',
      style: {
        'background-color': '#8B5CF6',
        'label': 'data(label)',
        'color': '#fff',
        'font-size': '10px',
        'width': '40px',
        'height': '40px',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': '8px',
      }
    },
    {
      selector: '.ip-node',
      style: {
        'background-color': '#EF4444',
        'shape': 'ellipse',
      }
    },
    {
      selector: '.domain-node',
      style: {
        'background-color': '#06B6D4',
        'shape': 'rectangle',
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#6B7280',
        'target-arrow-color': '#6B7280',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '8px',
        'color': '#9CA3AF',
        'text-rotation': 'autorotate',
      }
    },
  ];

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
          className="relative w-full max-w-5xl h-[80vh] glass-card rounded-xl overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between p-4 border-b border-white/10">
            <div>
              <h3 className="text-lg font-bold">{campaign.id} - Correlation Graph</h3>
              <p className="text-sm text-gray-500">Visualizing IOC relationships</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/10 rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          
          <div className="w-full h-[calc(100%-64px)]">
            <CytoscapeComponent
              elements={elements}
              layout={layout}
              stylesheet={stylesheet}
              style={{ width: '100%', height: '100%', backgroundColor: '#0B0F1A' }}
              cy={(cy) => {
                cyRef.current = cy;
                cy.on('tap', 'node', (evt) => {
                  const node = evt.target;
                  console.log(`Node: ${node.data('label')}\nType: ${node.data('type')}`);
                });
              }}
            />
          </div>
          
          <div className="absolute bottom-4 right-4 glass-card p-2 text-xs text-gray-500">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <span>IP Address</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-cyan-500"></div>
                <span>Domain</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 bg-purple-500"></div>
                <span>URL/Hash</span>
              </div>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
