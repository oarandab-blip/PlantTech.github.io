/* Plant Tech - JavaScript conectado con Flask */
"use strict";

const $ = (id) => document.getElementById(id);

const authSection = $("authSection");
const appSection = $("appSection");
const loginForm = $("loginForm");
const registerForm = $("registerForm");
const recuperacionForm = $("recuperacionForm");
const formularioPlanta = $("formularioPlanta");

const mensajeLogin = $("mensajeLogin");
const mensajeRegistro = $("mensajeRegistro");
const mensajeRecuperacion = $("mensajeRecuperacion");
const mensajePlanta = $("mensajePlanta");
const listaPlantas = $("listaPlantas");
const bienvenida = $("bienvenida");

let usuarioActual = null;

function mostrarMensaje(elemento, texto = "", tipo = "") {
    if (!elemento) return;
    elemento.textContent = texto;
    elemento.className = "mensaje";
    if (tipo) elemento.classList.add(tipo);
}

async function api(url, opciones = {}) {
    const respuesta = await fetch(url, {
        credentials: "same-origin",
        ...opciones
    });

    let datos = {};
    try {
        datos = await respuesta.json();
    } catch (_) {}

    if (!respuesta.ok) {
        throw new Error(
            datos.error || datos.message || `Error HTTP ${respuesta.status}`
        );
    }

    return datos;
}

function mostrarSolo(formulario) {
    loginForm.hidden = formulario !== loginForm;
    registerForm.hidden = formulario !== registerForm;
    recuperacionForm.hidden = formulario !== recuperacionForm;
    mostrarMensaje(mensajeLogin);
    mostrarMensaje(mensajeRegistro);
    mostrarMensaje(mensajeRecuperacion);
}

$("mostrarRegistro").addEventListener("click", () => mostrarSolo(registerForm));
$("mostrarLogin").addEventListener("click", () => mostrarSolo(loginForm));
$("mostrarRecuperacion").addEventListener("click", () => mostrarSolo(recuperacionForm));
$("volverLogin").addEventListener("click", () => {
    recuperacionForm.reset();
    mostrarSolo(loginForm);
});

registerForm.addEventListener("submit", async (evento) => {
    evento.preventDefault();

    const nombre = $("nombreUsuario").value.trim();
    const usuario = $("usuarioRegistro").value.trim().toLowerCase();
    const password = $("contrasenaRegistro").value;
    const confirmar = $("confirmarContrasena").value;
    const codigo_admin = $("codigoAdmin").value.trim();

    if (!nombre || !usuario || !password) {
        return mostrarMensaje(mensajeRegistro, "Completa todos los campos obligatorios.", "error");
    }
    if (!/^[a-z0-9_-]{3,30}$/.test(usuario)) {
        return mostrarMensaje(mensajeRegistro, "El usuario debe tener entre 3 y 30 caracteres.", "error");
    }
    if (password.length < 6) {
        return mostrarMensaje(mensajeRegistro, "La contraseña debe tener al menos 6 caracteres.", "error");
    }
    if (password !== confirmar) {
        return mostrarMensaje(mensajeRegistro, "Las contraseñas no coinciden.", "error");
    }

    try {
        const datos = await api("/api/register", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({nombre, usuario, password, codigo_admin})
        });

        registerForm.reset();
        $("usuarioLogin").value = usuario;
        mostrarSolo(loginForm);
        mostrarMensaje(mensajeLogin, datos.message || "Cuenta creada. Ahora puedes iniciar sesión.", "exito");
    } catch (error) {
        mostrarMensaje(mensajeRegistro, error.message, "error");
    }
});

loginForm.addEventListener("submit", async (evento) => {
    evento.preventDefault();

    const usuario = $("usuarioLogin").value.trim().toLowerCase();
    const password = $("contrasenaLogin").value;

    if (!usuario || !password) {
        return mostrarMensaje(mensajeLogin, "Ingresa usuario y contraseña.", "error");
    }

    try {
        mostrarMensaje(mensajeLogin, "Ingresando...");
        const datos = await api("/api/login", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({usuario, password})
        });

        usuarioActual = datos.usuario;
        mostrarAplicacion(usuarioActual);
        await cargarPlantas();
    } catch (error) {
        mostrarMensaje(mensajeLogin, error.message, "error");
    }
});

function mostrarAplicacion(usuario) {
    authSection.hidden = true;
    appSection.hidden = false;
    bienvenida.textContent = `Hola, ${usuario.nombre} 🌱`;
    $("enlaceAdmin").hidden = usuario.rol !== "admin";
    window.scrollTo({top: 0, behavior: "smooth"});
}

$("cerrarSesion").addEventListener("click", async () => {
    try {
        await api("/api/logout", {method: "POST"});
    } catch (_) {}

    usuarioActual = null;
    appSection.hidden = true;
    authSection.hidden = false;
    loginForm.reset();
    formularioPlanta.reset();
    mostrarSolo(loginForm);
});

recuperacionForm.addEventListener("submit", async (evento) => {
    evento.preventDefault();

    const usuario = $("usuarioRecuperacion").value.trim().toLowerCase();
    const nombre = $("nombreRecuperacion").value.trim();
    const password = $("nuevaContrasena").value;
    const confirmar = $("confirmarNuevaContrasena").value;

    if (!usuario || !nombre || !password || !confirmar) {
        return mostrarMensaje(mensajeRecuperacion, "Completa todos los campos.", "error");
    }
    if (password.length < 6) {
        return mostrarMensaje(mensajeRecuperacion, "La contraseña debe tener al menos 6 caracteres.", "error");
    }
    if (password !== confirmar) {
        return mostrarMensaje(mensajeRecuperacion, "Las contraseñas no coinciden.", "error");
    }

    try {
        const datos = await api("/api/recover", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                usuario,
                nombre,
                nueva_password: password
            })
        });

        recuperacionForm.reset();
        $("usuarioLogin").value = usuario;
        mostrarSolo(loginForm);
        mostrarMensaje(mensajeLogin, datos.message || "Contraseña actualizada.", "exito");
    } catch (error) {
        mostrarMensaje(mensajeRecuperacion, error.message, "error");
    }
});

async function cargarPlantas() {
    try {
        const datos = await api("/api/plants");
        mostrarPlantas(datos.plantas || []);
    } catch (error) {
        listaPlantas.innerHTML = `
            <div class="empty-state">
                <span>⚠️</span>
                <p>No se pudieron cargar las plantas.</p>
                <small>${escapeHtml(error.message)}</small>
            </div>`;
    }
}

function escapeHtml(valor) {
    return String(valor ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function fechaLocalISO(fecha = new Date()) {
    const anio = fecha.getFullYear();
    const mes = String(fecha.getMonth() + 1).padStart(2, "0");
    const dia = String(fecha.getDate()).padStart(2, "0");
    return `${anio}-${mes}-${dia}`;
}

function fechaLegible(fechaISO) {
    if (!fechaISO) return "Sin fecha";
    const fecha = new Date(`${fechaISO}T12:00:00`);
    if (Number.isNaN(fecha.getTime())) return fechaISO;
    return fecha.toLocaleDateString("es-CO");
}

const svg = (ruta) =>
    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ruta}</svg>`;
const ICONOS = {
    riego: svg('<path d="M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z"/>'),
    calcular: svg('<path d="M4 20V4M4 20h16M8 15l4-4 3 3 5-6"/>'),
    ia: svg('<path d="M12 3l1.8 4.7L18.5 9.5 13.8 11.3 12 16l-1.8-4.7L5.5 9.5l4.7-1.8z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8z"/>'),
    editar: svg('<path d="M4 20h4L19 9l-4-4L4 16z"/>'),
    eliminar: svg('<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>'),
};

function fmt(valor, decimales = 1) {
    const n = Number(valor);
    if (valor === null || valor === undefined || valor === "" || !Number.isFinite(n)) return "—";
    return n.toLocaleString("es-CO", {maximumFractionDigits: decimales});
}

function fechaCorta(fechaISO) {
    const fecha = new Date(`${fechaISO}T12:00:00`);
    if (Number.isNaN(fecha.getTime())) return "—";
    const meses = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"];
    return `${fecha.getDate()} ${meses[fecha.getMonth()]}`;
}

function infoEstadoRiego(planta) {
    const proxima = new Date(`${planta.fecha_riego}T12:00:00`);
    proxima.setDate(proxima.getDate() + Number(planta.frecuencia));
    const hoy = new Date(`${fechaLocalISO()}T12:00:00`);
    const dias = Math.round((proxima - hoy) / 86400000);
    if (Number.isNaN(dias)) {
        return {nivel: "ok", etiqueta: "Sin fecha de riego", dias: null, fechaProxima: ""};
    }
    const fechaProxima = fechaLocalISO(proxima);
    if (dias < 0) {
        const n = -dias;
        return {nivel: "atrasado", etiqueta: `Atrasada · hace ${n} ${n === 1 ? "día" : "días"}`, dias, fechaProxima};
    }
    if (dias === 0) return {nivel: "pronto", etiqueta: "Revisar hoy", dias, fechaProxima};
    if (dias === 1) return {nivel: "pronto", etiqueta: "Revisar mañana", dias, fechaProxima};
    return {nivel: "ok", etiqueta: `Al día · en ${dias} días`, dias, fechaProxima};
}

function actualizarResumen(plantas) {
    const estados = plantas.map(infoEstadoRiego);
    const futuras = estados.filter((e) => e.dias !== null && e.dias >= 0).map((e) => e.fechaProxima).sort();
    const poner = (id, valor) => { const el = $(id); if (el) el.textContent = valor; };
    poner("resumenTotal", plantas.length);
    poner("resumenAlDia", estados.filter((e) => e.nivel === "ok").length);
    poner("resumenProxima", futuras.length ? fechaCorta(futuras[0]) : "—");
}

function calcularEstadoRiego(planta) {
    const proxima = new Date(`${planta.fecha_riego}T12:00:00`);
    proxima.setDate(proxima.getDate() + Number(planta.frecuencia));
    const fechaProxima = fechaLocalISO(proxima);
    const hoy = fechaLocalISO();

    if (fechaProxima < hoy) return "La fecha estimada de revisión ya pasó.";
    if (fechaProxima === hoy) return "Hoy puedes revisar si la planta necesita agua.";
    return `Próxima revisión: ${fechaLegible(fechaProxima)}`;
}

function mostrarPlantas(plantas) {
    actualizarResumen(plantas);
    if (!plantas.length) {
        listaPlantas.innerHTML = `
            <div class="empty-state">
                <span>🪴</span>
                <p>Aún no has registrado plantas.</p>
                <small>Tu colección aparecerá aquí.</small>
            </div>`;
        return;
    }

    listaPlantas.innerHTML = plantas.map(crearTarjetaPlanta).join("");
    agregarEventosPlantas();
}

function textoCalculo(calculo) {
    const e = calculo.entradas || {};
    const r = calculo.resultado || {};
    if (calculo.modelo === "crecimiento") {
        return `Crecimiento: de ${fmt(e.altura_inicial)} cm a ${fmt(r.altura_estimada)} cm en ${fmt(e.dias, 0)} días`;
    }
    return `Humedad: de ${fmt(e.humedad_inicial, 0)} % a ${fmt(r.humedad_final)} % en ${fmt(e.dias, 0)} días`;
}

function crearHistorialRiego(planta) {
    const lista = planta.riegos || [];
    if (!lista.length) {
        return `<div class="seguimiento"><strong>Historial de riegos:</strong>
            <small>Aún no has registrado riegos. Pulsa «Registrar riego» cada vez que la riegues.</small></div>`;
    }
    const items = lista.map((r) => {
        const hora = String(r.creado_en || "").slice(11, 16);
        return `<li>${fechaLegible(r.fecha)}${hora ? ` · ${escapeHtml(hora)}` : ""}</li>`;
    }).join("");
    const total = planta.riegos_total || lista.length;
    const nota = total > lista.length ? ` <small>(${total} en total)</small>` : "";
    return `<div class="seguimiento"><strong>Historial de riegos (últimos ${lista.length}):</strong>${nota}
        <ul>${items}</ul></div>`;
}

function crearSeguimiento(planta) {
    const lista = planta.calculos || [];
    if (!lista.length) {
        return `<div class="seguimiento"><strong>Seguimiento:</strong>
            <small>Aún no hay cálculos guardados para esta planta.</small></div>`;
    }
    const items = lista.map((c) =>
        `<li>${fechaLegible(String(c.creado_en).slice(0, 10))} · ${escapeHtml(textoCalculo(c))}</li>`
    ).join("");
    return `<div class="seguimiento"><strong>Seguimiento (últimos cálculos):</strong>
        <ul>${items}</ul></div>`;
}

function crearInfoIA(planta) {
    const i = planta.info_ia;
    if (!i) return "";

    const lista = (titulo, items) => items && items.length
        ? `<p><strong>${titulo}</strong></p><ul>${items.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>`
        : "";
    const cientifico = i.nombre_cientifico ? ` · <em>${escapeHtml(i.nombre_cientifico)}</em>` : "";

    return `
        <details class="info-ia" id="infoIA-${planta.id}">
            <summary>
                <span>Ficha con IA${cientifico}</span>
                <span class="ver-cerrado">Ver ficha</span><span class="ver-abierto">Ocultar</span>
            </summary>
            <div class="info-ia-cuerpo">
                ${i.nombre_comun ? `<p class="info-ia-nombres">${escapeHtml(i.nombre_comun)}</p>` : ""}
                <p>${escapeHtml(i.resena)}</p>
                ${lista("Para qué sirve", i.usos)}
                ${lista("Cuidados básicos", i.cuidados)}
                ${i.precauciones ? `<p class="info-ia-aviso"><strong>Precaución:</strong> ${escapeHtml(i.precauciones)}</p>` : ""}
                <small>Información orientativa generada por IA; puede contener errores. No sustituye la consulta con un profesional de la salud.</small>
            </div>
        </details>`;
}

async function consultarInfoIA(id, boton) {
    const textoOriginal = boton.textContent;
    const htmlOriginal = boton.innerHTML;
    boton.disabled = true;
    boton.textContent = "Consultando…";
    try {
        const refrescar = textoOriginal.includes("Actualizar") ? "?refrescar=1" : "";
        await api(`/api/plants/${id}/info${refrescar}`, {method: "POST"});
        await cargarPlantas();
    } catch (error) {
        boton.disabled = false;
        boton.innerHTML = htmlOriginal;
        alert(error.message);
    }
}

function crearTarjetaPlanta(planta) {
    const estado = infoEstadoRiego(planta);
    const imagen = planta.imagen_url
        ? `<img class="imagen-planta" src="${escapeHtml(planta.imagen_url)}" alt="${escapeHtml(planta.nombre)}">`
        : `<div class="imagen-planta imagen-vacia" aria-hidden="true">🪴</div>`;
    const historial = `${crearHistorialRiego(planta)}${crearSeguimiento(planta)}`;

    return `
        <article class="planta" data-id="${planta.id}">
            ${imagen}
            <div class="planta-body">
                <div class="planta-cabecera">
                    <div>
                        <h3>${escapeHtml(planta.nombre)}</h3>
                        <small>${escapeHtml(planta.especie)}</small>
                    </div>
                    <span class="chip chip-${estado.nivel}">${escapeHtml(estado.etiqueta)}</span>
                </div>
                <div class="metricas">
                    <div>Último riego<b>${fechaCorta(planta.fecha_riego)}</b></div>
                    <div>Intervalo<b>${Number(planta.frecuencia)} días</b></div>
                    <div>Próxima revisión<b>${estado.fechaProxima ? fechaCorta(estado.fechaProxima) : "—"}</b></div>
                </div>
                ${planta.observaciones ? `<p class="planta-obs">${escapeHtml(planta.observaciones)}</p>` : ""}
                <details class="plegable">
                    <summary>Historial y cálculos</summary>
                    ${historial}
                </details>
                ${crearInfoIA(planta)}
                <div class="planta-actions">
                    <button type="button" class="btn btn-primary" data-accion="regar" data-id="${planta.id}">${ICONOS.riego}Registrar riego</button>
                    <a class="btn btn-secondary" href="/modelo?planta=${planta.id}">${ICONOS.calcular}Calcular crecimiento</a>
                    <button type="button" class="btn btn-ghost btn-ia" data-accion="info" data-id="${planta.id}">${ICONOS.ia}${planta.info_ia ? "Actualizar reseña" : "Reseña con IA"}</button>
                    <button type="button" class="btn-icono" data-accion="editar" data-id="${planta.id}" aria-label="Editar planta" title="Editar">${ICONOS.editar}</button>
                    <button type="button" class="btn-icono eliminar" data-accion="eliminar" data-id="${planta.id}" aria-label="Eliminar planta" title="Eliminar">${ICONOS.eliminar}</button>
                </div>
            </div>
        </article>`;
}

function agregarEventosPlantas() {
    listaPlantas.querySelectorAll("[data-accion]").forEach((boton) => {
        boton.addEventListener("click", () => {
            const accion = boton.dataset.accion;
            const id = boton.dataset.id;
            if (accion === "info") consultarInfoIA(id, boton);
            if (accion === "regar") registrarRiego(id);
            if (accion === "editar") editarPlanta(id);
            if (accion === "eliminar") eliminarPlanta(id);
        });
    });
}

async function registrarRiego(id) {
    if (!confirm("¿Deseas registrar el riego de esta planta?")) return;

    try {
        await api(`/api/plants/${id}/water`, {method: "POST"});
        await cargarPlantas();
    } catch (error) {
        alert(error.message);
    }
}

async function editarPlanta(id) {
    try {
        const datos = await api("/api/plants");
        const planta = (datos.plantas || []).find((item) => String(item.id) === String(id));

        if (!planta) return alert("No se encontró la planta.");

        const nombre = prompt("Nombre de la planta:", planta.nombre);
        if (nombre === null) return;

        const especie = prompt("Especie:", planta.especie);
        if (especie === null) return;

        const frecuencia = prompt("Intervalo de revisión en días:", planta.frecuencia);
        if (frecuencia === null) return;

        const observaciones = prompt("Observaciones:", planta.observaciones || "");
        if (observaciones === null) return;

        await api(`/api/plants/${id}`, {
            method: "PUT",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                nombre,
                especie,
                fechaRiego: planta.fecha_riego,
                frecuencia: Number(frecuencia),
                observaciones
            })
        });

        await cargarPlantas();
    } catch (error) {
        alert(error.message);
    }
}

async function eliminarPlanta(id) {
    if (!confirm("¿Seguro que deseas eliminar esta planta?")) return;

    try {
        await api(`/api/plants/${id}`, {method: "DELETE"});
        await cargarPlantas();
    } catch (error) {
        alert(error.message);
    }
}

formularioPlanta.addEventListener("submit", async (evento) => {
    evento.preventDefault();

    const datos = new FormData();
    datos.append("nombre", $("nombre").value.trim());
    datos.append("especie", $("especie").value.trim());
    datos.append("fechaRiego", $("fechaRiego").value);
    datos.append("frecuencia", $("frecuencia").value);
    datos.append("observaciones", $("observaciones").value.trim());

    const archivo = $("imagen").files[0];
    if (archivo) datos.append("imagen", archivo);

    try {
        mostrarMensaje(mensajePlanta, "Guardando planta...");
        const respuesta = await api("/api/plants", {
            method: "POST",
            body: datos
        });

        formularioPlanta.reset();
        $("frecuencia").value = 3;
        mostrarMensaje(mensajePlanta, respuesta.message || "Planta registrada correctamente.", "exito");
        await cargarPlantas();
    } catch (error) {
        mostrarMensaje(mensajePlanta, error.message, "error");
    }
});

async function comprobarSesion() {
    try {
        const datos = await api("/api/session");

        if (datos.authenticated && datos.usuario) {
            usuarioActual = datos.usuario;
            mostrarAplicacion(usuarioActual);
            await cargarPlantas();
            return;
        }
    } catch (error) {
        console.error("No se pudo comprobar la sesión:", error);
    }

    authSection.hidden = false;
    appSection.hidden = true;
    mostrarSolo(loginForm);
}

document.addEventListener("DOMContentLoaded", comprobarSesion);
