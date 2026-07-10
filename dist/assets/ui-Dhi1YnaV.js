function le(u){return u&&u.__esModule&&Object.prototype.hasOwnProperty.call(u,"default")?u.default:u}var Q={exports:{}},k={};/**
 * @license React
 * react.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */var K;function ce(){if(K)return k;K=1;var u=Symbol.for("react.element"),a=Symbol.for("react.portal"),c=Symbol.for("react.fragment"),l=Symbol.for("react.strict_mode"),M=Symbol.for("react.profiler"),y=Symbol.for("react.provider"),m=Symbol.for("react.context"),_=Symbol.for("react.forward_ref"),e=Symbol.for("react.suspense"),t=Symbol.for("react.memo"),r=Symbol.for("react.lazy"),o=Symbol.iterator;function s(n){return n===null||typeof n!="object"?null:(n=o&&n[o]||n["@@iterator"],typeof n=="function"?n:null)}var f={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},h=Object.assign,w={};function p(n,i,v){this.props=n,this.context=i,this.refs=w,this.updater=v||f}p.prototype.isReactComponent={},p.prototype.setState=function(n,i){if(typeof n!="object"&&typeof n!="function"&&n!=null)throw Error("setState(...): takes an object of state variables to update or a function which returns an object of state variables.");this.updater.enqueueSetState(this,n,i,"setState")},p.prototype.forceUpdate=function(n){this.updater.enqueueForceUpdate(this,n,"forceUpdate")};function L(){}L.prototype=p.prototype;function N(n,i,v){this.props=n,this.context=i,this.refs=w,this.updater=v||f}var C=N.prototype=new L;C.constructor=N,h(C,p.prototype),C.isPureReactComponent=!0;var S=Array.isArray,I=Object.prototype.hasOwnProperty,B={current:null},G={key:!0,ref:!0,__self:!0,__source:!0};function Y(n,i,v){var E,g={},A=null,b=null;if(i!=null)for(E in i.ref!==void 0&&(b=i.ref),i.key!==void 0&&(A=""+i.key),i)I.call(i,E)&&!G.hasOwnProperty(E)&&(g[E]=i[E]);var x=arguments.length-2;if(x===1)g.children=v;else if(1<x){for(var R=Array(x),z=0;z<x;z++)R[z]=arguments[z+2];g.children=R}if(n&&n.defaultProps)for(E in x=n.defaultProps,x)g[E]===void 0&&(g[E]=x[E]);return{$$typeof:u,type:n,key:A,ref:b,props:g,_owner:B.current}}function oe(n,i){return{$$typeof:u,type:n.type,key:i,ref:n.ref,props:n.props,_owner:n._owner}}function V(n){return typeof n=="object"&&n!==null&&n.$$typeof===u}function ae(n){var i={"=":"=0",":":"=2"};return"$"+n.replace(/[=:]/g,function(v){return i[v]})}var X=/\/+/g;function q(n,i){return typeof n=="object"&&n!==null&&n.key!=null?ae(""+n.key):i.toString(36)}function T(n,i,v,E,g){var A=typeof n;(A==="undefined"||A==="boolean")&&(n=null);var b=!1;if(n===null)b=!0;else switch(A){case"string":case"number":b=!0;break;case"object":switch(n.$$typeof){case u:case a:b=!0}}if(b)return b=n,g=g(b),n=E===""?"."+q(b,0):E,S(g)?(v="",n!=null&&(v=n.replace(X,"$&/")+"/"),T(g,i,v,"",function(z){return z})):g!=null&&(V(g)&&(g=oe(g,v+(!g.key||b&&b.key===g.key?"":(""+g.key).replace(X,"$&/")+"/")+n)),i.push(g)),1;if(b=0,E=E===""?".":E+":",S(n))for(var x=0;x<n.length;x++){A=n[x];var R=E+q(A,x);b+=T(A,i,v,R,g)}else if(R=s(n),typeof R=="function")for(n=R.call(n),x=0;!(A=n.next()).done;)A=A.value,R=E+q(A,x++),b+=T(A,i,v,R,g);else if(A==="object")throw i=String(n),Error("Objects are not valid as a React child (found: "+(i==="[object Object]"?"object with keys {"+Object.keys(n).join(", ")+"}":i)+"). If you meant to render a collection of children, use an array instead.");return b}function j(n,i,v){if(n==null)return n;var E=[],g=0;return T(n,E,"","",function(A){return i.call(v,A,g++)}),E}function se(n){if(n._status===-1){var i=n._result;i=i(),i.then(function(v){(n._status===0||n._status===-1)&&(n._status=1,n._result=v)},function(v){(n._status===0||n._status===-1)&&(n._status=2,n._result=v)}),n._status===-1&&(n._status=0,n._result=i)}if(n._status===1)return n._result.default;throw n._result}var P={current:null},H={transition:null},ie={ReactCurrentDispatcher:P,ReactCurrentBatchConfig:H,ReactCurrentOwner:B};function W(){throw Error("act(...) is not supported in production builds of React.")}return k.Children={map:j,forEach:function(n,i,v){j(n,function(){i.apply(this,arguments)},v)},count:function(n){var i=0;return j(n,function(){i++}),i},toArray:function(n){return j(n,function(i){return i})||[]},only:function(n){if(!V(n))throw Error("React.Children.only expected to receive a single React element child.");return n}},k.Component=p,k.Fragment=c,k.Profiler=M,k.PureComponent=N,k.StrictMode=l,k.Suspense=e,k.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=ie,k.act=W,k.cloneElement=function(n,i,v){if(n==null)throw Error("React.cloneElement(...): The argument must be a React element, but you passed "+n+".");var E=h({},n.props),g=n.key,A=n.ref,b=n._owner;if(i!=null){if(i.ref!==void 0&&(A=i.ref,b=B.current),i.key!==void 0&&(g=""+i.key),n.type&&n.type.defaultProps)var x=n.type.defaultProps;for(R in i)I.call(i,R)&&!G.hasOwnProperty(R)&&(E[R]=i[R]===void 0&&x!==void 0?x[R]:i[R])}var R=arguments.length-2;if(R===1)E.children=v;else if(1<R){x=Array(R);for(var z=0;z<R;z++)x[z]=arguments[z+2];E.children=x}return{$$typeof:u,type:n.type,key:g,ref:A,props:E,_owner:b}},k.createContext=function(n){return n={$$typeof:m,_currentValue:n,_currentValue2:n,_threadCount:0,Provider:null,Consumer:null,_defaultValue:null,_globalName:null},n.Provider={$$typeof:y,_context:n},n.Consumer=n},k.createElement=Y,k.createFactory=function(n){var i=Y.bind(null,n);return i.type=n,i},k.createRef=function(){return{current:null}},k.forwardRef=function(n){return{$$typeof:_,render:n}},k.isValidElement=V,k.lazy=function(n){return{$$typeof:r,_payload:{_status:-1,_result:n},_init:se}},k.memo=function(n,i){return{$$typeof:t,type:n,compare:i===void 0?null:i}},k.startTransition=function(n){var i=H.transition;H.transition={};try{n()}finally{H.transition=i}},k.unstable_act=W,k.useCallback=function(n,i){return P.current.useCallback(n,i)},k.useContext=function(n){return P.current.useContext(n)},k.useDebugValue=function(){},k.useDeferredValue=function(n){return P.current.useDeferredValue(n)},k.useEffect=function(n,i){return P.current.useEffect(n,i)},k.useId=function(){return P.current.useId()},k.useImperativeHandle=function(n,i,v){return P.current.useImperativeHandle(n,i,v)},k.useInsertionEffect=function(n,i){return P.current.useInsertionEffect(n,i)},k.useLayoutEffect=function(n,i){return P.current.useLayoutEffect(n,i)},k.useMemo=function(n,i){return P.current.useMemo(n,i)},k.useReducer=function(n,i,v){return P.current.useReducer(n,i,v)},k.useRef=function(n){return P.current.useRef(n)},k.useState=function(n){return P.current.useState(n)},k.useSyncExternalStore=function(n,i,v){return P.current.useSyncExternalStore(n,i,v)},k.useTransition=function(){return P.current.useTransition()},k.version="18.3.1",k}var Z;function ue(){return Z||(Z=1,Q.exports=ce()),Q.exports}var F=ue();const U=le(F);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const he=u=>u.replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase(),ee=(...u)=>u.filter((a,c,l)=>!!a&&a.trim()!==""&&l.indexOf(a)===c).join(" ").trim();/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */var fe={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor",strokeWidth:2,strokeLinecap:"round",strokeLinejoin:"round"};/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const de=F.forwardRef(({color:u="currentColor",size:a=24,strokeWidth:c=2,absoluteStrokeWidth:l,className:M="",children:y,iconNode:m,..._},e)=>F.createElement("svg",{ref:e,...fe,width:a,height:a,stroke:u,strokeWidth:l?Number(c)*24/Number(a):c,className:ee("lucide",M),..._},[...m.map(([t,r])=>F.createElement(t,r)),...Array.isArray(y)?y:[y]]));/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const d=(u,a)=>{const c=F.forwardRef(({className:l,...M},y)=>F.createElement(de,{ref:y,iconNode:a,className:ee(`lucide-${he(u)}`,l),...M}));return c.displayName=`${u}`,c};/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const xe=d("ArrowRight",[["path",{d:"M5 12h14",key:"1ays0h"}],["path",{d:"m12 5 7 7-7 7",key:"xquz4c"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const be=d("Bell",[["path",{d:"M10.268 21a2 2 0 0 0 3.464 0",key:"vwvbt9"}],["path",{d:"M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326",key:"11g9vi"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Se=d("Bluetooth",[["path",{d:"m7 7 10 10-5 5V2l5 5L7 17",key:"1q5490"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Pe=d("Camera",[["path",{d:"M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3l-2.5-3z",key:"1tc9qg"}],["circle",{cx:"12",cy:"13",r:"3",key:"1vg3eu"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ne=d("Check",[["path",{d:"M20 6 9 17l-5-5",key:"1gmf2c"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const ze=d("ChevronRight",[["path",{d:"m9 18 6-6-6-6",key:"mthhwq"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ie=d("CircleCheckBig",[["path",{d:"M21.801 10A10 10 0 1 1 17 3.335",key:"yps3ct"}],["path",{d:"m9 11 3 3L22 4",key:"1pflzl"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Le=d("Clock",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["polyline",{points:"12 6 12 12 16 14",key:"68esgv"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Oe=d("Copy",[["rect",{width:"14",height:"14",x:"8",y:"8",rx:"2",ry:"2",key:"17jyea"}],["path",{d:"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2",key:"zix9uf"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Fe=d("Cpu",[["rect",{width:"16",height:"16",x:"4",y:"4",rx:"2",key:"14l7u7"}],["rect",{width:"6",height:"6",x:"9",y:"9",rx:"1",key:"5aljv4"}],["path",{d:"M15 2v2",key:"13l42r"}],["path",{d:"M15 20v2",key:"15mkzm"}],["path",{d:"M2 15h2",key:"1gxd5l"}],["path",{d:"M2 9h2",key:"1bbxkp"}],["path",{d:"M20 15h2",key:"19e6y8"}],["path",{d:"M20 9h2",key:"19tzq7"}],["path",{d:"M9 2v2",key:"165o2o"}],["path",{d:"M9 20v2",key:"i2bqo8"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Be=d("Database",[["ellipse",{cx:"12",cy:"5",rx:"9",ry:"3",key:"msslwz"}],["path",{d:"M3 5V19A9 3 0 0 0 21 19V5",key:"1wlel7"}],["path",{d:"M3 12A9 3 0 0 0 21 12",key:"mv7ke4"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const De=d("Download",[["path",{d:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4",key:"ih7n3h"}],["polyline",{points:"7 10 12 15 17 10",key:"2ggqvy"}],["line",{x1:"12",x2:"12",y1:"15",y2:"3",key:"1vk2je"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Te=d("EyeOff",[["path",{d:"M10.733 5.076a10.744 10.744 0 0 1 11.205 6.575 1 1 0 0 1 0 .696 10.747 10.747 0 0 1-1.444 2.49",key:"ct8e1f"}],["path",{d:"M14.084 14.158a3 3 0 0 1-4.242-4.242",key:"151rxh"}],["path",{d:"M17.479 17.499a10.75 10.75 0 0 1-15.417-5.151 1 1 0 0 1 0-.696 10.75 10.75 0 0 1 4.446-5.143",key:"13bj9a"}],["path",{d:"m2 2 20 20",key:"1ooewy"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const je=d("Eye",[["path",{d:"M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0",key:"1nclc0"}],["circle",{cx:"12",cy:"12",r:"3",key:"1v7zrd"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const He=d("FileJson",[["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z",key:"1rqfz7"}],["path",{d:"M14 2v4a2 2 0 0 0 2 2h4",key:"tnqrlb"}],["path",{d:"M10 12a1 1 0 0 0-1 1v1a1 1 0 0 1-1 1 1 1 0 0 1 1 1v1a1 1 0 0 0 1 1",key:"1oajmo"}],["path",{d:"M14 18a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1 1 1 0 0 1-1-1v-1a1 1 0 0 0-1-1",key:"mpwhp6"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ue=d("File",[["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z",key:"1rqfz7"}],["path",{d:"M14 2v4a2 2 0 0 0 2 2h4",key:"tnqrlb"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const $e=d("FolderOpen",[["path",{d:"m6 14 1.5-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.54 6a2 2 0 0 1-1.95 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.69.9l.81 1.2a2 2 0 0 0 1.67.9H18a2 2 0 0 1 2 2v2",key:"usdka0"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ve=d("Globe",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20",key:"13o1zl"}],["path",{d:"M2 12h20",key:"9i4pu4"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const qe=d("HardDriveDownload",[["path",{d:"M12 2v8",key:"1q4o3n"}],["path",{d:"m16 6-4 4-4-4",key:"6wukr"}],["rect",{width:"20",height:"8",x:"2",y:"14",rx:"2",key:"w68u3i"}],["path",{d:"M6 18h.01",key:"uhywen"}],["path",{d:"M10 18h.01",key:"h775k"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Qe=d("Info",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"M12 16v-4",key:"1dtifu"}],["path",{d:"M12 8h.01",key:"e9boi3"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ge=d("Layers",[["path",{d:"M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z",key:"zw3jo"}],["path",{d:"M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12",key:"1wduqc"}],["path",{d:"M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17",key:"kqbvx6"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ye=d("Link2",[["path",{d:"M9 17H7A5 5 0 0 1 7 7h2",key:"8i5ue5"}],["path",{d:"M15 7h2a5 5 0 1 1 0 10h-2",key:"1b9ql8"}],["line",{x1:"8",x2:"16",y1:"12",y2:"12",key:"1jonct"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Xe=d("Lock",[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2",key:"1w4ew1"}],["path",{d:"M7 11V7a5 5 0 0 1 10 0v4",key:"fwvmzm"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const We=d("LogOut",[["path",{d:"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4",key:"1uf3rs"}],["polyline",{points:"16 17 21 12 16 7",key:"1gabdz"}],["line",{x1:"21",x2:"9",y1:"12",y2:"12",key:"1uyos4"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ke=d("Monitor",[["rect",{width:"20",height:"14",x:"2",y:"3",rx:"2",key:"48i651"}],["line",{x1:"8",x2:"16",y1:"21",y2:"21",key:"1svkeh"}],["line",{x1:"12",x2:"12",y1:"17",y2:"21",key:"vw1qmm"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ze=d("Network",[["rect",{x:"16",y:"16",width:"6",height:"6",rx:"1",key:"4q2zg0"}],["rect",{x:"2",y:"16",width:"6",height:"6",rx:"1",key:"8cvhb9"}],["rect",{x:"9",y:"2",width:"6",height:"6",rx:"1",key:"1egb70"}],["path",{d:"M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3",key:"1jsf9p"}],["path",{d:"M12 12V8",key:"2874zd"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Je=d("Palette",[["circle",{cx:"13.5",cy:"6.5",r:".5",fill:"currentColor",key:"1okk4w"}],["circle",{cx:"17.5",cy:"10.5",r:".5",fill:"currentColor",key:"f64h9f"}],["circle",{cx:"8.5",cy:"7.5",r:".5",fill:"currentColor",key:"fotxhn"}],["circle",{cx:"6.5",cy:"12.5",r:".5",fill:"currentColor",key:"qy21gx"}],["path",{d:"M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z",key:"12rzf8"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const et=d("QrCode",[["rect",{width:"5",height:"5",x:"3",y:"3",rx:"1",key:"1tu5fj"}],["rect",{width:"5",height:"5",x:"16",y:"3",rx:"1",key:"1v8r4q"}],["rect",{width:"5",height:"5",x:"3",y:"16",rx:"1",key:"1x03jg"}],["path",{d:"M21 16h-3a2 2 0 0 0-2 2v3",key:"177gqh"}],["path",{d:"M21 21v.01",key:"ents32"}],["path",{d:"M12 7v3a2 2 0 0 1-2 2H7",key:"8crl2c"}],["path",{d:"M3 12h.01",key:"nlz23k"}],["path",{d:"M12 3h.01",key:"n36tog"}],["path",{d:"M12 16v.01",key:"133mhm"}],["path",{d:"M16 12h1",key:"1slzba"}],["path",{d:"M21 12v.01",key:"1lwtk9"}],["path",{d:"M12 21v-1",key:"1880an"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const tt=d("Radio",[["path",{d:"M4.9 19.1C1 15.2 1 8.8 4.9 4.9",key:"1vaf9d"}],["path",{d:"M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5",key:"u1ii0m"}],["circle",{cx:"12",cy:"12",r:"2",key:"1c9p78"}],["path",{d:"M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5",key:"1j5fej"}],["path",{d:"M19.1 4.9C23 8.8 23 15.1 19.1 19",key:"10b0cb"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const rt=d("RefreshCw",[["path",{d:"M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8",key:"v9h5vc"}],["path",{d:"M21 3v5h-5",key:"1q7to0"}],["path",{d:"M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16",key:"3uifl3"}],["path",{d:"M8 16H3v5",key:"1cv678"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const nt=d("RotateCcw",[["path",{d:"M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8",key:"1357e3"}],["path",{d:"M3 3v5h5",key:"1xhq8a"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const ot=d("Scan",[["path",{d:"M3 7V5a2 2 0 0 1 2-2h2",key:"aa7l1z"}],["path",{d:"M17 3h2a2 2 0 0 1 2 2v2",key:"4qcy5o"}],["path",{d:"M21 17v2a2 2 0 0 1-2 2h-2",key:"6vwrx8"}],["path",{d:"M7 21H5a2 2 0 0 1-2-2v-2",key:"ioqczr"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const at=d("Settings",[["path",{d:"M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z",key:"1qme2f"}],["circle",{cx:"12",cy:"12",r:"3",key:"1v7zrd"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const st=d("ShieldCheck",[["path",{d:"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",key:"oel41y"}],["path",{d:"m9 12 2 2 4-4",key:"dzmm74"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const it=d("Shield",[["path",{d:"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z",key:"oel41y"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const lt=d("SlidersHorizontal",[["line",{x1:"21",x2:"14",y1:"4",y2:"4",key:"obuewd"}],["line",{x1:"10",x2:"3",y1:"4",y2:"4",key:"1q6298"}],["line",{x1:"21",x2:"12",y1:"12",y2:"12",key:"1iu8h1"}],["line",{x1:"8",x2:"3",y1:"12",y2:"12",key:"ntss68"}],["line",{x1:"21",x2:"16",y1:"20",y2:"20",key:"14d8ph"}],["line",{x1:"12",x2:"3",y1:"20",y2:"20",key:"m0wm8r"}],["line",{x1:"14",x2:"14",y1:"2",y2:"6",key:"14e1ph"}],["line",{x1:"8",x2:"8",y1:"10",y2:"14",key:"1i6ji0"}],["line",{x1:"16",x2:"16",y1:"18",y2:"22",key:"1lctlv"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const ct=d("Trash2",[["path",{d:"M3 6h18",key:"d0wm0j"}],["path",{d:"M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6",key:"4alrt4"}],["path",{d:"M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2",key:"v07s0e"}],["line",{x1:"10",x2:"10",y1:"11",y2:"17",key:"1uufr5"}],["line",{x1:"14",x2:"14",y1:"11",y2:"17",key:"xtxkd"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const ut=d("TriangleAlert",[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3",key:"wmoenq"}],["path",{d:"M12 9v4",key:"juzpu7"}],["path",{d:"M12 17h.01",key:"p32p05"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const ht=d("Upload",[["path",{d:"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4",key:"ih7n3h"}],["polyline",{points:"17 8 12 3 7 8",key:"t8dd8p"}],["line",{x1:"12",x2:"12",y1:"3",y2:"15",key:"widbto"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const ft=d("User",[["path",{d:"M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2",key:"975kel"}],["circle",{cx:"12",cy:"7",r:"4",key:"17ys0d"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const dt=d("VideoOff",[["path",{d:"M10.66 6H14a2 2 0 0 1 2 2v2.5l5.248-3.062A.5.5 0 0 1 22 7.87v8.196",key:"w8jjjt"}],["path",{d:"M16 16a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h2",key:"1xawa7"}],["path",{d:"m2 2 20 20",key:"1ooewy"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const yt=d("Volume2",[["path",{d:"M11 4.702a.705.705 0 0 0-1.203-.498L6.413 7.587A1.4 1.4 0 0 1 5.416 8H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2.416a1.4 1.4 0 0 1 .997.413l3.383 3.384A.705.705 0 0 0 11 19.298z",key:"uqj9uw"}],["path",{d:"M16 9a5 5 0 0 1 0 6",key:"1q6k2b"}],["path",{d:"M19.364 18.364a9 9 0 0 0 0-12.728",key:"ijwkga"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const pt=d("VolumeX",[["path",{d:"M11 4.702a.705.705 0 0 0-1.203-.498L6.413 7.587A1.4 1.4 0 0 1 5.416 8H3a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2.416a1.4 1.4 0 0 1 .997.413l3.383 3.384A.705.705 0 0 0 11 19.298z",key:"uqj9uw"}],["line",{x1:"22",x2:"16",y1:"9",y2:"15",key:"1ewh16"}],["line",{x1:"16",x2:"22",y1:"9",y2:"15",key:"5ykzw1"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const kt=d("Wifi",[["path",{d:"M12 20h.01",key:"zekei9"}],["path",{d:"M2 8.82a15 15 0 0 1 20 0",key:"dnpr2z"}],["path",{d:"M5 12.859a10 10 0 0 1 14 0",key:"1x1e6c"}],["path",{d:"M8.5 16.429a5 5 0 0 1 7 0",key:"1bycff"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const mt=d("X",[["path",{d:"M18 6 6 18",key:"1bl5f8"}],["path",{d:"m6 6 12 12",key:"d8bk6v"}]]);/**
 * @license lucide-react v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Mt=d("Zap",[["path",{d:"M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z",key:"1xq2db"}]]);var ye=Object.defineProperty,$=Object.getOwnPropertySymbols,te=Object.prototype.hasOwnProperty,re=Object.prototype.propertyIsEnumerable,J=(u,a,c)=>a in u?ye(u,a,{enumerable:!0,configurable:!0,writable:!0,value:c}):u[a]=c,pe=(u,a)=>{for(var c in a||(a={}))te.call(a,c)&&J(u,c,a[c]);if($)for(var c of $(a))re.call(a,c)&&J(u,c,a[c]);return u},ke=(u,a)=>{var c={};for(var l in u)te.call(u,l)&&a.indexOf(l)<0&&(c[l]=u[l]);if(u!=null&&$)for(var l of $(u))a.indexOf(l)<0&&re.call(u,l)&&(c[l]=u[l]);return c};/**
 * @license QR Code generator library (TypeScript)
 * Copyright (c) Project Nayuki.
 * SPDX-License-Identifier: MIT
 */var O;(u=>{const a=class{constructor(e,t,r,o){if(this.version=e,this.errorCorrectionLevel=t,this.modules=[],this.isFunction=[],e<a.MIN_VERSION||e>a.MAX_VERSION)throw new RangeError("Version value out of range");if(o<-1||o>7)throw new RangeError("Mask value out of range");this.size=e*4+17;let s=[];for(let h=0;h<this.size;h++)s.push(!1);for(let h=0;h<this.size;h++)this.modules.push(s.slice()),this.isFunction.push(s.slice());this.drawFunctionPatterns();const f=this.addEccAndInterleave(r);if(this.drawCodewords(f),o==-1){let h=1e9;for(let w=0;w<8;w++){this.applyMask(w),this.drawFormatBits(w);const p=this.getPenaltyScore();p<h&&(o=w,h=p),this.applyMask(w)}}y(0<=o&&o<=7),this.mask=o,this.applyMask(o),this.drawFormatBits(o),this.isFunction=[]}static encodeText(e,t){const r=u.QrSegment.makeSegments(e);return a.encodeSegments(r,t)}static encodeBinary(e,t){const r=u.QrSegment.makeBytes(e);return a.encodeSegments([r],t)}static encodeSegments(e,t,r=1,o=40,s=-1,f=!0){if(!(a.MIN_VERSION<=r&&r<=o&&o<=a.MAX_VERSION)||s<-1||s>7)throw new RangeError("Invalid value");let h,w;for(h=r;;h++){const C=a.getNumDataCodewords(h,t)*8,S=_.getTotalBits(e,h);if(S<=C){w=S;break}if(h>=o)throw new RangeError("Data too long")}for(const C of[a.Ecc.MEDIUM,a.Ecc.QUARTILE,a.Ecc.HIGH])f&&w<=a.getNumDataCodewords(h,C)*8&&(t=C);let p=[];for(const C of e){l(C.mode.modeBits,4,p),l(C.numChars,C.mode.numCharCountBits(h),p);for(const S of C.getData())p.push(S)}y(p.length==w);const L=a.getNumDataCodewords(h,t)*8;y(p.length<=L),l(0,Math.min(4,L-p.length),p),l(0,(8-p.length%8)%8,p),y(p.length%8==0);for(let C=236;p.length<L;C^=253)l(C,8,p);let N=[];for(;N.length*8<p.length;)N.push(0);return p.forEach((C,S)=>N[S>>>3]|=C<<7-(S&7)),new a(h,t,N,s)}getModule(e,t){return 0<=e&&e<this.size&&0<=t&&t<this.size&&this.modules[t][e]}getModules(){return this.modules}drawFunctionPatterns(){for(let r=0;r<this.size;r++)this.setFunctionModule(6,r,r%2==0),this.setFunctionModule(r,6,r%2==0);this.drawFinderPattern(3,3),this.drawFinderPattern(this.size-4,3),this.drawFinderPattern(3,this.size-4);const e=this.getAlignmentPatternPositions(),t=e.length;for(let r=0;r<t;r++)for(let o=0;o<t;o++)r==0&&o==0||r==0&&o==t-1||r==t-1&&o==0||this.drawAlignmentPattern(e[r],e[o]);this.drawFormatBits(0),this.drawVersion()}drawFormatBits(e){const t=this.errorCorrectionLevel.formatBits<<3|e;let r=t;for(let s=0;s<10;s++)r=r<<1^(r>>>9)*1335;const o=(t<<10|r)^21522;y(o>>>15==0);for(let s=0;s<=5;s++)this.setFunctionModule(8,s,M(o,s));this.setFunctionModule(8,7,M(o,6)),this.setFunctionModule(8,8,M(o,7)),this.setFunctionModule(7,8,M(o,8));for(let s=9;s<15;s++)this.setFunctionModule(14-s,8,M(o,s));for(let s=0;s<8;s++)this.setFunctionModule(this.size-1-s,8,M(o,s));for(let s=8;s<15;s++)this.setFunctionModule(8,this.size-15+s,M(o,s));this.setFunctionModule(8,this.size-8,!0)}drawVersion(){if(this.version<7)return;let e=this.version;for(let r=0;r<12;r++)e=e<<1^(e>>>11)*7973;const t=this.version<<12|e;y(t>>>18==0);for(let r=0;r<18;r++){const o=M(t,r),s=this.size-11+r%3,f=Math.floor(r/3);this.setFunctionModule(s,f,o),this.setFunctionModule(f,s,o)}}drawFinderPattern(e,t){for(let r=-4;r<=4;r++)for(let o=-4;o<=4;o++){const s=Math.max(Math.abs(o),Math.abs(r)),f=e+o,h=t+r;0<=f&&f<this.size&&0<=h&&h<this.size&&this.setFunctionModule(f,h,s!=2&&s!=4)}}drawAlignmentPattern(e,t){for(let r=-2;r<=2;r++)for(let o=-2;o<=2;o++)this.setFunctionModule(e+o,t+r,Math.max(Math.abs(o),Math.abs(r))!=1)}setFunctionModule(e,t,r){this.modules[t][e]=r,this.isFunction[t][e]=!0}addEccAndInterleave(e){const t=this.version,r=this.errorCorrectionLevel;if(e.length!=a.getNumDataCodewords(t,r))throw new RangeError("Invalid argument");const o=a.NUM_ERROR_CORRECTION_BLOCKS[r.ordinal][t],s=a.ECC_CODEWORDS_PER_BLOCK[r.ordinal][t],f=Math.floor(a.getNumRawDataModules(t)/8),h=o-f%o,w=Math.floor(f/o);let p=[];const L=a.reedSolomonComputeDivisor(s);for(let C=0,S=0;C<o;C++){let I=e.slice(S,S+w-s+(C<h?0:1));S+=I.length;const B=a.reedSolomonComputeRemainder(I,L);C<h&&I.push(0),p.push(I.concat(B))}let N=[];for(let C=0;C<p[0].length;C++)p.forEach((S,I)=>{(C!=w-s||I>=h)&&N.push(S[C])});return y(N.length==f),N}drawCodewords(e){if(e.length!=Math.floor(a.getNumRawDataModules(this.version)/8))throw new RangeError("Invalid argument");let t=0;for(let r=this.size-1;r>=1;r-=2){r==6&&(r=5);for(let o=0;o<this.size;o++)for(let s=0;s<2;s++){const f=r-s,w=(r+1&2)==0?this.size-1-o:o;!this.isFunction[w][f]&&t<e.length*8&&(this.modules[w][f]=M(e[t>>>3],7-(t&7)),t++)}}y(t==e.length*8)}applyMask(e){if(e<0||e>7)throw new RangeError("Mask value out of range");for(let t=0;t<this.size;t++)for(let r=0;r<this.size;r++){let o;switch(e){case 0:o=(r+t)%2==0;break;case 1:o=t%2==0;break;case 2:o=r%3==0;break;case 3:o=(r+t)%3==0;break;case 4:o=(Math.floor(r/3)+Math.floor(t/2))%2==0;break;case 5:o=r*t%2+r*t%3==0;break;case 6:o=(r*t%2+r*t%3)%2==0;break;case 7:o=((r+t)%2+r*t%3)%2==0;break;default:throw new Error("Unreachable")}!this.isFunction[t][r]&&o&&(this.modules[t][r]=!this.modules[t][r])}}getPenaltyScore(){let e=0;for(let s=0;s<this.size;s++){let f=!1,h=0,w=[0,0,0,0,0,0,0];for(let p=0;p<this.size;p++)this.modules[s][p]==f?(h++,h==5?e+=a.PENALTY_N1:h>5&&e++):(this.finderPenaltyAddHistory(h,w),f||(e+=this.finderPenaltyCountPatterns(w)*a.PENALTY_N3),f=this.modules[s][p],h=1);e+=this.finderPenaltyTerminateAndCount(f,h,w)*a.PENALTY_N3}for(let s=0;s<this.size;s++){let f=!1,h=0,w=[0,0,0,0,0,0,0];for(let p=0;p<this.size;p++)this.modules[p][s]==f?(h++,h==5?e+=a.PENALTY_N1:h>5&&e++):(this.finderPenaltyAddHistory(h,w),f||(e+=this.finderPenaltyCountPatterns(w)*a.PENALTY_N3),f=this.modules[p][s],h=1);e+=this.finderPenaltyTerminateAndCount(f,h,w)*a.PENALTY_N3}for(let s=0;s<this.size-1;s++)for(let f=0;f<this.size-1;f++){const h=this.modules[s][f];h==this.modules[s][f+1]&&h==this.modules[s+1][f]&&h==this.modules[s+1][f+1]&&(e+=a.PENALTY_N2)}let t=0;for(const s of this.modules)t=s.reduce((f,h)=>f+(h?1:0),t);const r=this.size*this.size,o=Math.ceil(Math.abs(t*20-r*10)/r)-1;return y(0<=o&&o<=9),e+=o*a.PENALTY_N4,y(0<=e&&e<=2568888),e}getAlignmentPatternPositions(){if(this.version==1)return[];{const e=Math.floor(this.version/7)+2,t=this.version==32?26:Math.ceil((this.version*4+4)/(e*2-2))*2;let r=[6];for(let o=this.size-7;r.length<e;o-=t)r.splice(1,0,o);return r}}static getNumRawDataModules(e){if(e<a.MIN_VERSION||e>a.MAX_VERSION)throw new RangeError("Version number out of range");let t=(16*e+128)*e+64;if(e>=2){const r=Math.floor(e/7)+2;t-=(25*r-10)*r-55,e>=7&&(t-=36)}return y(208<=t&&t<=29648),t}static getNumDataCodewords(e,t){return Math.floor(a.getNumRawDataModules(e)/8)-a.ECC_CODEWORDS_PER_BLOCK[t.ordinal][e]*a.NUM_ERROR_CORRECTION_BLOCKS[t.ordinal][e]}static reedSolomonComputeDivisor(e){if(e<1||e>255)throw new RangeError("Degree out of range");let t=[];for(let o=0;o<e-1;o++)t.push(0);t.push(1);let r=1;for(let o=0;o<e;o++){for(let s=0;s<t.length;s++)t[s]=a.reedSolomonMultiply(t[s],r),s+1<t.length&&(t[s]^=t[s+1]);r=a.reedSolomonMultiply(r,2)}return t}static reedSolomonComputeRemainder(e,t){let r=t.map(o=>0);for(const o of e){const s=o^r.shift();r.push(0),t.forEach((f,h)=>r[h]^=a.reedSolomonMultiply(f,s))}return r}static reedSolomonMultiply(e,t){if(e>>>8||t>>>8)throw new RangeError("Byte out of range");let r=0;for(let o=7;o>=0;o--)r=r<<1^(r>>>7)*285,r^=(t>>>o&1)*e;return y(r>>>8==0),r}finderPenaltyCountPatterns(e){const t=e[1];y(t<=this.size*3);const r=t>0&&e[2]==t&&e[3]==t*3&&e[4]==t&&e[5]==t;return(r&&e[0]>=t*4&&e[6]>=t?1:0)+(r&&e[6]>=t*4&&e[0]>=t?1:0)}finderPenaltyTerminateAndCount(e,t,r){return e&&(this.finderPenaltyAddHistory(t,r),t=0),t+=this.size,this.finderPenaltyAddHistory(t,r),this.finderPenaltyCountPatterns(r)}finderPenaltyAddHistory(e,t){t[0]==0&&(e+=this.size),t.pop(),t.unshift(e)}};let c=a;c.MIN_VERSION=1,c.MAX_VERSION=40,c.PENALTY_N1=3,c.PENALTY_N2=3,c.PENALTY_N3=40,c.PENALTY_N4=10,c.ECC_CODEWORDS_PER_BLOCK=[[-1,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],[-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28],[-1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],[-1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30]],c.NUM_ERROR_CORRECTION_BLOCKS=[[-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25],[-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49],[-1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68],[-1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81]],u.QrCode=c;function l(e,t,r){if(t<0||t>31||e>>>t)throw new RangeError("Value out of range");for(let o=t-1;o>=0;o--)r.push(e>>>o&1)}function M(e,t){return(e>>>t&1)!=0}function y(e){if(!e)throw new Error("Assertion error")}const m=class{constructor(e,t,r){if(this.mode=e,this.numChars=t,this.bitData=r,t<0)throw new RangeError("Invalid argument");this.bitData=r.slice()}static makeBytes(e){let t=[];for(const r of e)l(r,8,t);return new m(m.Mode.BYTE,e.length,t)}static makeNumeric(e){if(!m.isNumeric(e))throw new RangeError("String contains non-numeric characters");let t=[];for(let r=0;r<e.length;){const o=Math.min(e.length-r,3);l(parseInt(e.substr(r,o),10),o*3+1,t),r+=o}return new m(m.Mode.NUMERIC,e.length,t)}static makeAlphanumeric(e){if(!m.isAlphanumeric(e))throw new RangeError("String contains unencodable characters in alphanumeric mode");let t=[],r;for(r=0;r+2<=e.length;r+=2){let o=m.ALPHANUMERIC_CHARSET.indexOf(e.charAt(r))*45;o+=m.ALPHANUMERIC_CHARSET.indexOf(e.charAt(r+1)),l(o,11,t)}return r<e.length&&l(m.ALPHANUMERIC_CHARSET.indexOf(e.charAt(r)),6,t),new m(m.Mode.ALPHANUMERIC,e.length,t)}static makeSegments(e){return e==""?[]:m.isNumeric(e)?[m.makeNumeric(e)]:m.isAlphanumeric(e)?[m.makeAlphanumeric(e)]:[m.makeBytes(m.toUtf8ByteArray(e))]}static makeEci(e){let t=[];if(e<0)throw new RangeError("ECI assignment value out of range");if(e<128)l(e,8,t);else if(e<16384)l(2,2,t),l(e,14,t);else if(e<1e6)l(6,3,t),l(e,21,t);else throw new RangeError("ECI assignment value out of range");return new m(m.Mode.ECI,0,t)}static isNumeric(e){return m.NUMERIC_REGEX.test(e)}static isAlphanumeric(e){return m.ALPHANUMERIC_REGEX.test(e)}getData(){return this.bitData.slice()}static getTotalBits(e,t){let r=0;for(const o of e){const s=o.mode.numCharCountBits(t);if(o.numChars>=1<<s)return 1/0;r+=4+s+o.bitData.length}return r}static toUtf8ByteArray(e){e=encodeURI(e);let t=[];for(let r=0;r<e.length;r++)e.charAt(r)!="%"?t.push(e.charCodeAt(r)):(t.push(parseInt(e.substr(r+1,2),16)),r+=2);return t}};let _=m;_.NUMERIC_REGEX=/^[0-9]*$/,_.ALPHANUMERIC_REGEX=/^[A-Z0-9 $%*+.\/:-]*$/,_.ALPHANUMERIC_CHARSET="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:",u.QrSegment=_})(O||(O={}));(u=>{(a=>{const c=class{constructor(M,y){this.ordinal=M,this.formatBits=y}};let l=c;l.LOW=new c(0,1),l.MEDIUM=new c(1,0),l.QUARTILE=new c(2,3),l.HIGH=new c(3,2),a.Ecc=l})(u.QrCode||(u.QrCode={}))})(O||(O={}));(u=>{(a=>{const c=class{constructor(M,y){this.modeBits=M,this.numBitsCharCount=y}numCharCountBits(M){return this.numBitsCharCount[Math.floor((M+7)/17)]}};let l=c;l.NUMERIC=new c(1,[10,12,14]),l.ALPHANUMERIC=new c(2,[9,11,13]),l.BYTE=new c(4,[8,16,16]),l.KANJI=new c(8,[8,10,12]),l.ECI=new c(7,[0,0,0]),a.Mode=l})(u.QrSegment||(u.QrSegment={}))})(O||(O={}));var D=O;/**
 * @license qrcode.react
 * Copyright (c) Paul O'Shannessy
 * SPDX-License-Identifier: ISC
 */var me={L:D.QrCode.Ecc.LOW,M:D.QrCode.Ecc.MEDIUM,Q:D.QrCode.Ecc.QUARTILE,H:D.QrCode.Ecc.HIGH},Me=128,we="L",ve="#FFFFFF",Ce="#000000",ge=!1,ne=4,Ee=.1;function _e(u,a=0){const c=[];return u.forEach(function(l,M){let y=null;l.forEach(function(m,_){if(!m&&y!==null){c.push(`M${y+a} ${M+a}h${_-y}v1H${y+a}z`),y=null;return}if(_===l.length-1){if(!m)return;y===null?c.push(`M${_+a},${M+a} h1v1H${_+a}z`):c.push(`M${y+a},${M+a} h${_+1-y}v1H${y+a}z`);return}m&&y===null&&(y=_)})}),c.join("")}function Re(u,a){return u.slice().map((c,l)=>l<a.y||l>=a.y+a.h?c:c.map((M,y)=>y<a.x||y>=a.x+a.w?M:!1))}function Ae(u,a,c,l){if(l==null)return null;const M=c?ne:0,y=u.length+M*2,m=Math.floor(a*Ee),_=y/a,e=(l.width||m)*_,t=(l.height||m)*_,r=l.x==null?u.length/2-e/2:l.x*_,o=l.y==null?u.length/2-t/2:l.y*_;let s=null;if(l.excavate){let f=Math.floor(r),h=Math.floor(o),w=Math.ceil(e+r-f),p=Math.ceil(t+o-h);s={x:f,y:h,w,h:p}}return{x:r,y:o,h:t,w:e,excavation:s}}(function(){try{new Path2D().addPath(new Path2D)}catch{return!1}return!0})();function wt(u){const a=u,{value:c,size:l=Me,level:M=we,bgColor:y=ve,fgColor:m=Ce,includeMargin:_=ge,imageSettings:e}=a,t=ke(a,["value","size","level","bgColor","fgColor","includeMargin","imageSettings"]);let r=D.QrCode.encodeText(c,me[M]).getModules();const o=_?ne:0,s=r.length+o*2,f=Ae(r,l,_,e);let h=null;e!=null&&f!=null&&(f.excavation!=null&&(r=Re(r,f.excavation)),h=U.createElement("image",{xlinkHref:e.src,height:f.h,width:f.w,x:f.x+o,y:f.y+o,preserveAspectRatio:"none"}));const w=_e(r,o);return U.createElement("svg",pe({height:l,width:l,viewBox:`0 0 ${s} ${s}`},t),U.createElement("path",{fill:y,d:`M0,0 h${s}v${s}H0z`,shapeRendering:"crispEdges"}),U.createElement("path",{fill:m,d:w,shapeRendering:"crispEdges"}),h)}export{xe as A,Se as B,Ie as C,De as D,Te as E,Ue as F,Ve as G,qe as H,Qe as I,tt as J,at as K,Xe as L,Ke as M,Ze as N,U as O,Je as P,et as Q,rt as R,it as S,ut as T,ft as U,yt as V,kt as W,mt as X,Mt as Z,F as a,je as b,ht as c,Ne as d,Oe as e,Pe as f,le as g,Ye as h,$e as i,wt as j,Le as k,Be as l,lt as m,st as n,Fe as o,Ge as p,be as q,ue as r,pt as s,He as t,ct as u,nt as v,We as w,ot as x,dt as y,ze as z};
