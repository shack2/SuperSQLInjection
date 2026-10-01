//@name: Oracle DUNION
//@usage: payload
//@enable: false
//@description: 数字+UNION→数字DUNION（Oracle）
function tamper(payload){ return payload ? payload.replace(/(\d+)\s+(UNION )/gi, '$1D$2') : payload; }