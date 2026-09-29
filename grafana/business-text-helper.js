// Cole em Business Text > JavaScript > Before Content Rendering.
// Registra um helper que converte o texto JSON do item em uma lista iteravel.
// Forma documentada em
// https://grafana.com/docs/plugins/marcusolsson-dynamictext-panel/latest/javascript-code/
// Nao use "Handlebars.registerHelper" (global), use context.handlebars.
context.handlebars.registerHelper('parseJSON', (text) => {
  try {
    return JSON.parse(text);
  } catch (e) {
    return [];
  }
});
