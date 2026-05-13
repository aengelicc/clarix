import React from 'react';
import { AlertTriangle, CheckCircle, AlertOctagon } from 'lucide-react';

export default function RiskScore({ score }) {
  let color, bg, icon, label;

  if (score >= 75) {
    color = 'text-red-600';
    bg = 'bg-red-50 border-red-200';
    icon = <AlertOctagon size={24} className="text-red-600" />;
    label = 'Critical Risk';
  } else if (score >= 50) {
    color = 'text-orange-600';
    bg = 'bg-orange-50 border-orange-200';
    icon = <AlertTriangle size={24} className="text-orange-600" />;
    label = 'High Risk';
  } else if (score >= 25) {
    color = 'text-yellow-600';
    bg = 'bg-yellow-50 border-yellow-200';
    icon = <AlertTriangle size={24} className="text-yellow-600" />;
    label = 'Medium Risk';
  } else {
    color = 'text-green-600';
    bg = 'bg-green-50 border-green-200';
    icon = <CheckCircle size={24} className="text-green-600" />;
    label = 'Low Risk';
  }

  const circumference = 2 * Math.PI * 36;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={`card ${bg} flex items-center gap-5`}>
      <div className="relative w-24 h-24 shrink-0">
        <svg className="w-24 h-24 -rotate-90" viewBox="0 0 80 80">
          <circle
            cx="40"
            cy="40"
            r="36"
            fill="none"
            stroke="currentColor"
            strokeWidth="6"
            className="text-slate-200"
          />
          <circle
            cx="40"
            cy="40"
            r="36"
            fill="none"
            stroke="currentColor"
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className={color}
            style={{ transition: 'stroke-dashoffset 1s ease-out' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-xl font-bold ${color}`}>{score}</span>
        </div>
      </div>
      <div>
        <div className="flex items-center gap-2 mb-1">
          {icon}
          <span className={`font-semibold ${color}`}>{label}</span>
        </div>
        <p className="text-sm text-slate-600">Overall project risk assessment</p>
      </div>
    </div>
  );
}
