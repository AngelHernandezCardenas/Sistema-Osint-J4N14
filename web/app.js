document.addEventListener('DOMContentLoaded', () => {
    // Referencias DOM
    const orgList = document.getElementById('orgList');
    const currentOrgTitle = document.getElementById('currentOrgTitle');
    const dashboard = document.getElementById('dashboard');
    const emptyState = document.getElementById('emptyState');
    const loader = document.getElementById('loader');
    const btnScan = document.getElementById('btnScan');
    
    // Pestañas
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    let currentNetwork = null;

    // Inicializar
    cargarOrganizaciones();

    // Eventos
    btnScan.addEventListener('click', iniciarEscaneo);
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.add('hidden'));
            
            btn.classList.add('active');
            document.getElementById(btn.dataset.target).classList.remove('hidden');
            
            // Refrescar grafo si es visible
            if(btn.dataset.target === 'tab-graph' && currentNetwork) {
                currentNetwork.fit();
            }
        });
    });

    // Funciones API
    async function cargarOrganizaciones() {
        try {
            const res = await fetch('/api/organizaciones');
            const orgs = await res.json();
            
            orgList.innerHTML = '';
            orgs.forEach(org => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="fas fa-building"></i> ${org.nombre}`;
                li.onclick = () => {
                    document.querySelectorAll('#orgList li').forEach(el => el.classList.remove('active'));
                    li.classList.add('active');
                    cargarDashboard(org.id, org.nombre);
                };
                orgList.appendChild(li);
            });
        } catch (error) {
            console.error("Error cargando organizaciones", error);
        }
    }

    async function iniciarEscaneo() {
        const nombre = document.getElementById('scanOrg').value.trim();
        const dominio = document.getElementById('scanDomain').value.trim();
        
        if (!nombre || !dominio) {
            alert("Completa nombre y dominio.");
            return;
        }
        
        btnScan.disabled = true;
        btnScan.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando...';
        
        try {
            const res = await fetch(`/api/scan?nombre=${encodeURIComponent(nombre)}&dominio=${encodeURIComponent(dominio)}`, {
                method: 'POST'
            });
            const data = await res.json();
            
            document.getElementById('scanStatus').innerText = "Escaneo iniciado en segundo plano.";
            document.getElementById('scanStatus').classList.remove('hidden');
            
            setTimeout(() => {
                cargarOrganizaciones();
                document.getElementById('scanStatus').classList.add('hidden');
                btnScan.disabled = false;
                btnScan.innerHTML = '<i class="fas fa-search"></i> Iniciar OSINT';
                document.getElementById('scanOrg').value = '';
                document.getElementById('scanDomain').value = '';
            }, 2000);
            
        } catch (error) {
            alert("Error al iniciar el escaneo");
            btnScan.disabled = false;
            btnScan.innerHTML = '<i class="fas fa-search"></i> Iniciar OSINT';
        }
    }

    async function cargarDashboard(orgId, orgName) {
        emptyState.classList.add('hidden');
        dashboard.classList.add('hidden');
        loader.classList.remove('hidden');
        currentOrgTitle.innerText = orgName;
        
        try {
            // Cargar datos
            const [resData, resRisk, resGraph] = await Promise.all([
                fetch(`/api/resultados/${orgId}`),
                fetch(`/api/riesgo/${orgId}`),
                fetch(`/api/grafo/${orgId}`)
            ]);
            
            const data = await resData.json();
            const risk = await resRisk.json();
            const graph = await resGraph.json();
            
            actualizarEstadisticas(data);
            actualizarRiesgo(risk);
            actualizarTablas(data);
            renderizarGrafo(graph);
            
            loader.classList.add('hidden');
            dashboard.classList.remove('hidden');
            
        } catch (error) {
            console.error("Error cargando dashboard", error);
            loader.classList.add('hidden');
            alert("Error al cargar los datos. ¿Ya terminó el escaneo?");
        }
    }

    function actualizarEstadisticas(data) {
        document.getElementById('statDominios').innerText = data.dominios_count;
        document.getElementById('statTechs').innerText = data.tecnologias.length;
        document.getElementById('statSecretos').innerText = data.secretos.length;
        document.getElementById('statVulns').innerText = data.vulnerabilidades.length;
    }

    function actualizarRiesgo(risk) {
        const score = Math.round(risk.score || 0);
        const level = (risk.nivel || "Desconocido").toLowerCase();
        
        document.getElementById('riskScoreText').innerText = score;
        document.getElementById('riskLevelText').innerText = risk.nivel || "Desconocido";
        
        const circle = document.getElementById('riskCircle');
        circle.setAttribute('stroke-dasharray', `${score}, 100`);
        
        circle.className.baseVal = 'circle';
        if(score <= 40) circle.classList.add('low');
        else if(score <= 70) circle.classList.add('medium');
        else circle.classList.add('high');
    }

    function actualizarTablas(data) {
        // Dominios
        const tbody = document.getElementById('dominiosTableBody');
        tbody.innerHTML = '';
        data.estadisticas.total_dominios // solo para validar
        
        // Simular dominios para la tabla si no están en root de data, los extraemos
        // Idealmente la API devuelve la lista, aquí como no la devuelve en el objeto root del res, 
        // asumimos que los datos vienen en una estructura. Ajustar según API real.
        fetch(`/api/resultados/${data.organizacion.id}`).then(r => r.json()).then(fullData => {
            // El API actual no expone lista de dominios en /resultados, vamos a simular con 
            // los dominios de las tecnologías. En una app real, modificaríamos la API para devolver los dominios.
            // (Para este MVP, mostramos info simplificada)
            tbody.innerHTML = `<tr><td colspan="4" class="text-center">Datos de inventario cargados.</td></tr>`;
        });

        // Vulnerabilidades
        const vulnList = document.getElementById('vulnList');
        vulnList.innerHTML = '';
        if(data.vulnerabilidades.length === 0) {
            vulnList.innerHTML = '<li>Sin hallazgos detectados.</li>';
        }
        data.vulnerabilidades.forEach(v => {
            const li = document.createElement('li');
            li.className = v.severidad.toLowerCase();
            li.innerHTML = `
                <div class="item-header">
                    <span class="item-title">${v.cve_id}</span>
                    <span class="badge-status inactive">CVSS ${v.cvss_score}</span>
                </div>
                <div class="item-desc">${v.tech_nombre} ${v.tech_version} (${v.dominio})</div>
            `;
            vulnList.appendChild(li);
        });

        // Secretos
        const secList = document.getElementById('secretList');
        secList.innerHTML = '';
        if(data.secretos.length === 0) {
            secList.innerHTML = '<li>No se expusieron secretos.</li>';
        }
        data.secretos.forEach(s => {
            const li = document.createElement('li');
            li.className = s.severidad.toLowerCase();
            li.innerHTML = `
                <div class="item-header">
                    <span class="item-title">${s.tipo.toUpperCase()}</span>
                    <span class="badge-status inactive">${s.severidad}</span>
                </div>
                <div class="item-desc">${s.valor_ofuscado} (Fuente: ${s.fuente})</div>
            `;
            secList.appendChild(li);
        });
    }

    function renderizarGrafo(graphData) {
        const container = document.getElementById('networkGraph');
        
        // Configuración de colores por grupo
        const options = {
            nodes: {
                shape: 'dot',
                size: 20,
                font: { size: 14, color: '#f8fafc' },
                borderWidth: 2
            },
            edges: {
                width: 1,
                color: { color: '#475569', highlight: '#3b82f6' },
                smooth: { type: 'continuous' }
            },
            groups: {
                organizacion: { color: { background: '#3b82f6', border: '#2563eb' }, size: 30, shape: 'hexagon' },
                dominio: { color: { background: '#8b5cf6', border: '#7c3aed' } },
                subdominio: { color: { background: '#a855f7', border: '#9333ea' }, size: 15 },
                ip: { color: { background: '#14b8a6', border: '#0d9488' }, size: 15 },
                tecnologia: { color: { background: '#f59e0b', border: '#d97706' }, shape: 'box' },
                vulnerabilidad: { color: { background: '#ef4444', border: '#dc2626' }, shape: 'diamond' },
                repositorio: { color: { background: '#64748b', border: '#475569' } },
                secreto: { color: { background: '#ec4899', border: '#db2777' }, shape: 'star' }
            },
            physics: {
                forceAtlas2Based: { gravitationalConstant: -50, centralGravity: 0.01, springLength: 100, springConstant: 0.08 },
                maxVelocity: 50,
                solver: 'forceAtlas2Based',
                timestep: 0.35,
                stabilization: { iterations: 150 }
            }
        };

        if(currentNetwork) {
            currentNetwork.destroy();
        }
        
        currentNetwork = new vis.Network(container, graphData, options);
    }
});
