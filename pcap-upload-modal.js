// PCAP Upload Modal with Drag & Drop
class PcapUploadModal {
    constructor() {
        this.apiBase = 'http://localhost:5000/api';
        this.selectedFile = null;
        this.init();
    }

    init() {
        this.createModal();
        this.setupEventListeners();
    }

    createModal() {
        const modalHTML = `
            <div id="pcapUploadModal" class="fixed inset-0 bg-black bg-opacity-80 hidden flex items-center justify-center z-50">
                <div class="glass-panel rounded-lg max-w-2xl w-full mx-4 p-6">
                    <!-- Header -->
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="cyber-font text-2xl font-bold text-cyber-blue">
                            📁 PCAP File Analysis
                        </h3>
                        <button onclick="pcapUploadModal.close()" class="text-gray-400 hover:text-white text-2xl">
                            ✕
                        </button>
                    </div>

                    <!-- Tabs -->
                    <div class="flex space-x-2 mb-4">
                        <button id="uploadTab" class="tab-btn active px-4 py-2 rounded text-sm font-bold">
                            Upload New
                        </button>
                        <button id="existingTab" class="tab-btn px-4 py-2 rounded text-sm font-bold">
                            Select Existing
                        </button>
                    </div>

                    <!-- Upload Section -->
                    <div id="uploadSection" class="tab-content">
                        <!-- Drag & Drop Zone -->
                        <div id="dropZone" class="border-2 border-dashed border-cyber-blue rounded-lg p-8 text-center mb-4 cursor-pointer hover:bg-gray-800 transition">
                            <div class="text-cyber-blue text-5xl mb-3">📦</div>
                            <h4 class="text-white font-bold mb-2">Drag & Drop PCAP File Here</h4>
                            <p class="text-gray-400 text-sm mb-3">or click to browse</p>
                            <input type="file" id="pcapFileInput" accept=".pcap,.pcapng" class="hidden">
                            <button onclick="document.getElementById('pcapFileInput').click()" 
                                    class="bg-cyber-blue text-black px-4 py-2 rounded font-bold hover:bg-opacity-80">
                                Browse Files
                            </button>
                        </div>

                        <!-- Selected File Info -->
                        <div id="selectedFileInfo" class="hidden bg-gray-800 rounded-lg p-4 mb-4">
                            <div class="flex items-center justify-between">
                                <div>
                                    <div class="text-white font-bold" id="fileName"></div>
                                    <div class="text-gray-400 text-sm" id="fileSize"></div>
                                </div>
                                <button onclick="pcapUploadModal.clearFile()" class="text-red-400 hover:text-red-300">
                                    Remove
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Existing Files Section -->
                    <div id="existingSection" class="tab-content hidden">
                        <div class="bg-gray-800 rounded-lg p-4 max-h-64 overflow-y-auto">
                            <div id="existingFilesList" class="space-y-2">
                                <div class="text-gray-400 text-center py-4">Loading PCAP files...</div>
                            </div>
                        </div>
                    </div>

                    <!-- Analysis Options -->
                    <div class="mb-6">
                        <h4 class="text-white font-bold mb-3">Analysis Options</h4>
                        <div class="grid grid-cols-2 gap-3">
                            <label class="flex items-center space-x-2 text-gray-300 text-sm">
                                <input type="checkbox" id="opt_timing" checked class="w-4 h-4">
                                <span>Timing Correlation</span>
                            </label>
                            <label class="flex items-center space-x-2 text-gray-300 text-sm">
                                <input type="checkbox" id="opt_traffic" checked class="w-4 h-4">
                                <span>Traffic Analysis</span>
                            </label>
                            <label class="flex items-center space-x-2 text-gray-300 text-sm">
                                <input type="checkbox" id="opt_fingerprint" checked class="w-4 h-4">
                                <span>Website Fingerprinting</span>
                            </label>
                            <label class="flex items-center space-x-2 text-gray-300 text-sm">
                                <input type="checkbox" id="opt_geo" checked class="w-4 h-4">
                                <span>Geo-Location</span>
                            </label>
                        </div>
                    </div>

                    <!-- Progress Bar -->
                    <div id="uploadProgress" class="hidden mb-4">
                        <div class="flex justify-between text-sm text-gray-400 mb-1">
                            <span id="progressText">Analyzing...</span>
                            <span id="progressPercent">0%</span>
                        </div>
                        <div class="bg-gray-700 rounded-full h-3 overflow-hidden">
                            <div id="progressBar" class="bg-cyber-blue h-full transition-all duration-300" style="width: 0%"></div>
                        </div>
                    </div>

                    <!-- Action Buttons -->
                    <div class="flex space-x-3">
                        <button id="analyzeBtn" onclick="pcapUploadModal.analyze()" 
                                class="flex-1 bg-matrix-green text-black font-bold py-3 rounded hover:bg-opacity-80 disabled:opacity-50 disabled:cursor-not-allowed">
                            🔍 Analyze PCAP
                        </button>
                        <button onclick="pcapUploadModal.close()" 
                                class="px-6 bg-gray-700 text-white font-bold py-3 rounded hover:bg-gray-600">
                            Cancel
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }

    setupEventListeners() {
        // Tab switching
        document.getElementById('uploadTab').addEventListener('click', () => this.switchTab('upload'));
        document.getElementById('existingTab').addEventListener('click', () => this.switchTab('existing'));

        // Drag & Drop
        const dropZone = document.getElementById('dropZone');
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('bg-gray-800', 'border-matrix-green');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('bg-gray-800', 'border-matrix-green');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('bg-gray-800', 'border-matrix-green');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFileSelect(files[0]);
            }
        });

        // File input
        document.getElementById('pcapFileInput').addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFileSelect(e.target.files[0]);
            }
        });
    }

    switchTab(tab) {
        const uploadTab = document.getElementById('uploadTab');
        const existingTab = document.getElementById('existingTab');
        const uploadSection = document.getElementById('uploadSection');
        const existingSection = document.getElementById('existingSection');

        if (tab === 'upload') {
            uploadTab.classList.add('active', 'bg-cyber-blue', 'text-black');
            uploadTab.classList.remove('bg-gray-700', 'text-gray-300');
            existingTab.classList.remove('active', 'bg-cyber-blue', 'text-black');
            existingTab.classList.add('bg-gray-700', 'text-gray-300');
            uploadSection.classList.remove('hidden');
            existingSection.classList.add('hidden');
        } else {
            existingTab.classList.add('active', 'bg-cyber-blue', 'text-black');
            existingTab.classList.remove('bg-gray-700', 'text-gray-300');
            uploadTab.classList.remove('active', 'bg-cyber-blue', 'text-black');
            uploadTab.classList.add('bg-gray-700', 'text-gray-300');
            existingSection.classList.remove('hidden');
            uploadSection.classList.add('hidden');
            this.loadExistingFiles();
        }
    }

    handleFileSelect(file) {
        if (!file.name.endsWith('.pcap') && !file.name.endsWith('.pcapng')) {
            this.showNotification('Please select a valid PCAP file', 'error');
            return;
        }

        this.selectedFile = file;
        
        // Show file info
        document.getElementById('fileName').textContent = file.name;
        document.getElementById('fileSize').textContent = this.formatFileSize(file.size);
        document.getElementById('selectedFileInfo').classList.remove('hidden');
        document.getElementById('analyzeBtn').disabled = false;
    }

    clearFile() {
        this.selectedFile = null;
        document.getElementById('selectedFileInfo').classList.add('hidden');
        document.getElementById('pcapFileInput').value = '';
        document.getElementById('analyzeBtn').disabled = true;
    }

    async loadExistingFiles() {
        const listContainer = document.getElementById('existingFilesList');
        listContainer.innerHTML = '<div class="text-gray-400 text-center py-4">Loading...</div>';

        try {
            const response = await fetch(`${this.apiBase}/pcap/list`);
            const data = await response.json();

            if (data.files && data.files.length > 0) {
                listContainer.innerHTML = '';
                data.files.forEach(file => {
                    const fileItem = document.createElement('div');
                    fileItem.className = 'bg-gray-700 rounded p-3 hover:bg-gray-600 cursor-pointer flex justify-between items-center';
                    fileItem.innerHTML = `
                        <div>
                            <div class="text-white font-bold text-sm">${file.name}</div>
                            <div class="text-gray-400 text-xs">${this.formatFileSize(file.size)} • ${new Date(file.modified * 1000).toLocaleString()}</div>
                        </div>
                        <button class="bg-cyber-blue text-black px-3 py-1 rounded text-xs font-bold hover:bg-opacity-80">
                            Select
                        </button>
                    `;
                    fileItem.querySelector('button').addEventListener('click', () => this.selectExistingFile(file.path));
                    listContainer.appendChild(fileItem);
                });
            } else {
                listContainer.innerHTML = '<div class="text-gray-400 text-center py-4">No PCAP files found</div>';
            }
        } catch (error) {
            listContainer.innerHTML = '<div class="text-red-400 text-center py-4">Failed to load files</div>';
        }
    }

    async selectExistingFile(filePath) {
        this.selectedFile = { path: filePath, existing: true };
        document.getElementById('analyzeBtn').disabled = false;
        this.showNotification('File selected: ' + filePath.split(/[/\\]/).pop(), 'success');
    }

    async analyze() {
        if (!this.selectedFile) {
            this.showNotification('Please select a PCAP file', 'error');
            return;
        }

        const progressDiv = document.getElementById('uploadProgress');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const progressPercent = document.getElementById('progressPercent');
        const analyzeBtn = document.getElementById('analyzeBtn');

        analyzeBtn.disabled = true;
        progressDiv.classList.remove('hidden');
        progressText.textContent = 'Uploading...';

        try {
            let analyzeUrl;

            // Upload new file or use existing
            if (this.selectedFile.existing) {
                // Use existing file
                analyzeUrl = `${this.apiBase}/correlation/analyze-pcap`;
                progressBar.style.width = '30%';
                progressPercent.textContent = '30%';
                progressText.textContent = 'Analyzing packets...';

                const response = await fetch(analyzeUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ pcap_path: this.selectedFile.path })
                });

                const result = await response.json();
                this.handleAnalysisResult(result);

            } else {
                // Upload new file
                const formData = new FormData();
                formData.append('file', this.selectedFile);

                progressBar.style.width = '20%';
                progressPercent.textContent = '20%';

                const uploadResponse = await fetch(`${this.apiBase}/pcap/upload`, {
                    method: 'POST',
                    body: formData
                });

                const uploadResult = await uploadResponse.json();

                if (uploadResult.status === 'success') {
                    progressBar.style.width = '50%';
                    progressPercent.textContent = '50%';
                    progressText.textContent = 'Analyzing packets...';

                    // Analyze uploaded file
                    const analyzeResponse = await fetch(`${this.apiBase}/correlation/analyze-pcap`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ pcap_path: uploadResult.file_path })
                    });

                    const result = await analyzeResponse.json();
                    this.handleAnalysisResult(result);
                } else {
                    throw new Error(uploadResult.message || 'Upload failed');
                }
            }

        } catch (error) {
            console.error('Analysis error:', error);
            this.showNotification('Analysis failed: ' + error.message, 'error');
            analyzeBtn.disabled = false;
            progressDiv.classList.add('hidden');
        }
    }

    handleAnalysisResult(result) {
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const progressPercent = document.getElementById('progressPercent');

        progressBar.style.width = '100%';
        progressPercent.textContent = '100%';
        progressText.textContent = 'Analysis complete!';

        setTimeout(() => {
            this.close();
            
            if (result.status === 'success' || result.results) {
                this.showNotification('✓ PCAP analysis completed successfully!', 'success');
                
                // Update dashboard with results
                if (window.correlationDashboard) {
                    window.correlationDashboard.correlationData = result.results || result;
                    window.correlationDashboard.updateDashboard();
                }
                
                // Trigger page-wide update
                if (window.updateCorrelationResults) {
                    window.updateCorrelationResults(result.results || result);
                }
            } else {
                this.showNotification('Analysis completed with warnings', 'warning');
            }
        }, 1000);
    }

    open() {
        document.getElementById('pcapUploadModal').classList.remove('hidden');
        document.getElementById('pcapUploadModal').classList.add('flex');
    }

    close() {
        document.getElementById('pcapUploadModal').classList.add('hidden');
        document.getElementById('pcapUploadModal').classList.remove('flex');
        this.clearFile();
        document.getElementById('uploadProgress').classList.add('hidden');
        document.getElementById('progressBar').style.width = '0%';
        document.getElementById('analyzeBtn').disabled = false;
    }

    formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    showNotification(message, type = 'info') {
        if (window.showNotification) {
            window.showNotification(message, type);
        } else {
            alert(message);
        }
    }
}

// Initialize modal
const pcapUploadModal = new PcapUploadModal();

// Add CSS for active tabs
const style = document.createElement('style');
style.textContent = `
    .tab-btn {
        background: #374151;
        color: #9ca3af;
        transition: all 0.3s;
    }
    .tab-btn.active {
        background: #00d4ff;
        color: #000;
    }
`;
document.head.appendChild(style);
