import SwiftUI
import DLPCore

/// The popover UI shown from the menu-bar item.
struct StatusView: View {
    @EnvironmentObject var model: AgentModel
    var onToggleEnforcement: () -> Void
    var onConfirmWarning: () -> Void
    var onDismissWarning: () -> Void
    var onQuit: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let pending = model.pendingWarning {
                warningBanner(pending)
                Divider()
            }
            stats
            Divider()
            activity
            Divider()
            footer
        }
        .frame(width: 380)
    }

    private func warningBanner(_ pending: AgentModel.PendingWarning) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text("Confirmation required").font(.subheadline.bold())
            }
            Text("\(pending.summary) was held before reaching \(pending.destination). Send it anyway?")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(role: .destructive, action: onConfirmWarning) {
                    Text("Send anyway").frame(maxWidth: .infinity)
                }
                Button(action: onDismissWarning) {
                    Text("Keep blocked").frame(maxWidth: .infinity)
                }
            }
            .controlSize(.small)
        }
        .padding(12)
        .background(Color.orange.opacity(0.10))
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: model.running ? "shield.lefthalf.filled" : "shield.slash")
                .foregroundStyle(model.running ? .green : .secondary)
                .font(.title2)
            VStack(alignment: .leading, spacing: 1) {
                Text("Sentinel AI-DLP").font(.headline)
                Text(model.running ? "Protecting clipboard egress" : "Stopped")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: Binding(get: { model.enforcing }, set: { _ in onToggleEnforcement() }))
                .toggleStyle(.switch).labelsHidden()
        }
        .padding(12)
    }

    private var stats: some View {
        HStack(spacing: 0) {
            stat("\(model.totalEvents)", "Events", .primary)
            Divider().frame(height: 28)
            stat("\(model.blockedCount)", "Blocked", .red)
            Divider().frame(height: 28)
            stat("\(model.redactedCount)", "Redacted", .blue)
            Divider().frame(height: 28)
            stat("\(model.warnedCount)", "Warned", .orange)
        }
        .padding(.vertical, 10)
    }

    private func stat(_ value: String, _ label: String, _ color: Color) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.title3.monospacedDigit().bold()).foregroundStyle(color)
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }

    private var activity: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Recent activity").font(.caption.bold()).foregroundStyle(.secondary)
                .padding(.horizontal, 12).padding(.top, 8).padding(.bottom, 4)
            if model.recent.isEmpty {
                Text("No sensitive data detected yet. Copy a test secret to try it.")
                    .font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, 12).padding(.bottom, 10)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(model.recent.prefix(20)) { row($0) }
                    }
                }
                .frame(height: 220)
            }
        }
    }

    private func row(_ a: AgentModel.Activity) -> some View {
        HStack(alignment: .top, spacing: 8) {
            badge(a.action)
            VStack(alignment: .leading, spacing: 2) {
                Text(a.findingNames.isEmpty ? a.reason : a.findingNames.joined(separator: ", "))
                    .font(.caption).lineLimit(2)
                Text("\(a.channel.displayName) → \(a.destination)")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            Text(a.date, style: .time).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    private func badge(_ action: PolicyAction) -> some View {
        let (text, color): (String, Color) = {
            switch action {
            case .allow: return ("ALLOW", .green)
            case .audit: return ("AUDIT", .cyan)
            case .redact: return ("REDACT", .blue)
            case .warn: return ("WARN", .orange)
            case .block: return ("BLOCK", .red)
            case .quarantine: return ("QUAR", .purple)
            }
        }()
        return Text(text)
            .font(.system(size: 9, weight: .bold))
            .padding(.horizontal, 5).padding(.vertical, 2)
            .background(color.opacity(0.18)).foregroundStyle(color)
            .clipShape(RoundedRectangle(cornerRadius: 4))
    }

    private var footer: some View {
        HStack {
            Text("\(model.patternCount) patterns · \(model.serviceCount) AI services")
                .font(.caption2).foregroundStyle(.secondary)
            Spacer()
            Button("Quit", action: onQuit).controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }
}
