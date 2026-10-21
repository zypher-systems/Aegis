// Shared by the root layout (server) and the theme provider (client), so it
// carries no "use client".

export const THEME_KEY = "aegis-theme";

// Runs in <head> before first paint, so a stored light choice never flashes
// dark. Dark is the default: only an explicit choice switches to light.
export const THEME_INIT = `try{if(localStorage.getItem("${THEME_KEY}")==="light"){var c=document.documentElement.classList;c.remove("dark");c.add("light")}}catch(e){}`;
