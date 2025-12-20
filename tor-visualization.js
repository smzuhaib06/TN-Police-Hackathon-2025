// TOR Circuit Visualization Component
class TorVisualization {
    constructor() {
        this.container = null;
        this.nodes = [
            { id: 'user', x: 18, y: 45, label: 'New York', type: 'user', ip: '192.168.1.10 (USA)' },
            { id: 'guard', x: 55, y: 32, label: 'Germany', type: 'guard', subLabel: 'Guard Node' },
            { id: 'exit', x: 78, y: 25, label: 'Russia', type: 'exit', subLabel: 'Exit Node', ip: '185.12.34.56' },
            { id: 'dest', x: 88, y: 42, label: 'Japan', type: 'dest', subLabel: 'Target Server', ip: '203.0.113.1' },
            // Decoration nodes with corrected positions
            { id: 'dec1', x: 18, y: 18, label: 'Canada', type: 'guard' },
            { id: 'dec2', x: 32, y: 82, label: 'Brazil', type: 'guard' },
            { id: 'dec3', x: 72, y: 48, label: 'India', type: 'guard' },
            { id: 'dec4', x: 85, y: 85, label: 'Australia', type: 'exit' },
        ];
        this.init();
    }

    init() {
        this.createVisualization();
        this.startAnimation();
    }

    createVisualization() {
        const container = document.getElementById('worldMap');
        if (!container) return;

        container.innerHTML = `
            <div class="relative w-full h-full bg-slate-950 rounded-lg overflow-hidden">
                <!-- Background Map -->
                <div class="absolute inset-0 opacity-30 pointer-events-none"
                     style="background-image: url('https://upload.wikimedia.org/wikipedia/commons/e/ec/World_map_blank_without_borders.svg');
                            background-size: cover;
                            background-position: center;
                            filter: invert(1) hue-rotate(180deg) brightness(0.7);">
                </div>

                <!-- SVG Layer for Lines -->
                <svg class="absolute inset-0 w-full h-full pointer-events-none z-10" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid meet">
                    <defs>
                        <linearGradient id="gradientPath" x1="0%" y1="0%" x2="100%" y2="0%">
                            <stop offset="0%" stop-color="#22d3ee" stop-opacity="0" />
                            <stop offset="10%" stop-color="#22d3ee" stop-opacity="1" />
                            <stop offset="90%" stop-color="#22d3ee" stop-opacity="1" />
                            <stop offset="100%" stop-color="#22d3ee" stop-opacity="0" />
                        </linearGradient>
                    </defs>
                    
                    <!-- TOR Circuit Paths -->
                      <path id="torPath1" d="M 26 38 Q 37 25 49 26" 
                          fill="none" stroke="#22d3ee" stroke-width="2" 
                          stroke-linecap="round" opacity="0.8"
                          style="filter: drop-shadow(0 0 4px #22d3ee);">
                        <animate attributeName="stroke-dasharray" 
                                 values="0,100;20,80;40,60;60,40;80,20;100,0" 
                                 dur="2s" repeatCount="indefinite"/>
                    </path>
                    
                      <path id="torPath2" d="M 49 26 Q 58 20 68 22" 
                          fill="none" stroke="#22d3ee" stroke-width="2" 
                          stroke-linecap="round" opacity="0.8"
                          style="filter: drop-shadow(0 0 4px #22d3ee);">
                        <animate attributeName="stroke-dasharray" 
                                 values="0,100;20,80;40,60;60,40;80,20;100,0" 
                                 dur="2s" begin="0.5s" repeatCount="indefinite"/>
                    </path>
                    
                      <path id="torPath3" d="M 68 22 Q 77 28 86 40" 
                          fill="none" stroke="#22d3ee" stroke-width="2" 
                          stroke-linecap="round" opacity="0.8"
                          style="filter: drop-shadow(0 0 4px #22d3ee);">
                        <animate attributeName="stroke-dasharray" 
                                 values="0,100;20,80;40,60;60,40;80,20;100,0" 
                                 dur="2s" begin="1s" repeatCount="indefinite"/>
                    </path>

                    <!-- Correlation Attack Path -->
                      <path id="correlationPath" d="M 26 38 Q 56 50 86 40" 
                          fill="none" stroke="#ef4444" stroke-width="2" 
                          stroke-dasharray="6 4" stroke-opacity="0.6">
                    </path>

                    <!-- Moving Data Packets -->
                    <circle r="0.8" fill="white" opacity="0.9">
                        <animateMotion dur="3s" repeatCount="indefinite" 
                                       path="M 26 38 Q 37 25 49 26 Q 58 20 68 22 Q 77 28 86 40" />
                    </circle>
                </svg>

                <!-- HTML Layer for Nodes -->
                <div class="absolute inset-0 z-20" id="nodeContainer">
                    ${this.renderNodes()}
                </div>




            </div>
        `;

        this.addStyles();
    }

    renderNodes() {
        return this.nodes.map(node => {
            const colors = this.getNodeColors(node.type);
            const icon = this.getNodeIcon(node.type);
            
            return `
                <div class="absolute flex flex-col items-center group cursor-pointer" 
                     style="left: ${node.x}%; top: ${node.y}%;" 
                     data-node-id="${node.id}" 
                     onclick="window.liveDataManager?.selectNode('${node.id}')">
                    
                    ${node.ip ? `
                        <div class="absolute ${node.type === 'user' ? 'top-10' : '-top-12'} whitespace-nowrap z-40 opacity-0 group-hover:opacity-100 transition-opacity">
                            <div class="bg-slate-800/90 text-xs px-2 py-1 rounded border border-slate-600 text-slate-300 backdrop-blur-sm">
                                <div class="text-slate-400">
                                    ${node.name || node.label}: <span class="text-white font-mono">${node.ip}</span>
                                    ${node.bandwidth ? `<br/>BW: ${Math.floor(node.bandwidth/1000)}KB/s` : ''}
                                </div>
                            </div>
                        </div>
                    ` : ''}

                    <div class="relative w-8 h-8 rounded-full flex items-center justify-center shadow-lg ${colors} z-10 transition-transform hover:scale-110">
                        ${icon}
                        <div class="absolute inset-0 rounded-full animate-ping opacity-20 ${colors}"></div>
                    </div>

                    <span class="mt-2 text-xs font-bold tracking-wide text-white uppercase drop-shadow-md">
                        ${node.label}
                    </span>
                </div>
            `;
        }).join('');
    }

    getNodeColors(type) {
        switch(type) {
            case 'user': return 'bg-blue-500 shadow-blue-500/50';
            case 'guard': return 'bg-green-500 shadow-green-500/50';
            case 'exit': return 'bg-red-500 shadow-red-500/50';
            case 'dest': return 'bg-emerald-400 shadow-emerald-400/50';
            default: return 'bg-slate-500';
        }
    }

    getNodeIcon(type) {
        switch(type) {
            case 'user':
                return `<svg class="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"/>
                </svg>`;
            case 'dest':
                return `<svg class="w-4 h-4 text-slate-900" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v10a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm3.293 1.293a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 01-1.414-1.414L7.586 10 5.293 7.707a1 1 0 010-1.414zM11 12a1 1 0 100 2h3a1 1 0 100-2h-3z" clip-rule="evenodd"/>
                </svg>`;
            default:
                return `<div class="w-4 h-4 bg-white/90 rounded-full"></div>`;
        }
    }

    addStyles() {
        if (document.getElementById('torVisualizationStyles')) return;

        const style = document.createElement('style');
        style.id = 'torVisualizationStyles';
        style.textContent = `
            @keyframes fade-in {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .animate-fade-in {
                animation: fade-in 0.5s ease-out;
            }
            
            #torPath1, #torPath2, #torPath3 {
                stroke-dasharray: 100;
                stroke-dashoffset: 100;
                animation: drawPath 2s ease-in-out infinite;
            }
            
            @keyframes drawPath {
                0% { stroke-dashoffset: 100; }
                50% { stroke-dashoffset: 0; }
                100% { stroke-dashoffset: -100; }
            }
        `;
        document.head.appendChild(style);
        
        // Add highlight styles
        const highlightStyle = document.createElement('style');
        highlightStyle.textContent = `
            .highlighted {
                animation: highlight-pulse 2s ease-in-out infinite;
                transform: scale(1.2) !important;
            }
            
            @keyframes highlight-pulse {
                0%, 100% { box-shadow: 0 0 20px rgba(0, 212, 255, 0.8); }
                50% { box-shadow: 0 0 30px rgba(0, 212, 255, 1); }
            }
        `;
        document.head.appendChild(highlightStyle);
    }

    startAnimation() {
        // Update node states periodically
        setInterval(() => {
            this.updateNodeStates();
        }, 5000);
    }

    updateNodeStates() {
        // Simulate dynamic node state changes
        const nodeContainer = document.getElementById('nodeContainer');
        if (nodeContainer) {
            // Add subtle animations to show activity
            const nodes = nodeContainer.querySelectorAll('.group');
            nodes.forEach(node => {
                node.style.transform = 'scale(1.05)';
                setTimeout(() => {
                    node.style.transform = 'scale(1)';
                }, 200);
            });
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('worldMap')) {
        window.torVisualization = new TorVisualization();
    }
});

// Export for global access
window.TorVisualization = TorVisualization;