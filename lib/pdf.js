const PDFDocument = require('pdfkit');

// Truncate long strings — PDFKit wraps at spaces only, so an unbroken long
// word (or a missing value) would overflow the fixed column widths.
const trunc = (s, n = 50) => {
  const str = String(s ?? '').replace(/[\x00-\x1F\x7F]/g, '');
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
};

/**
 * Generate a purchase order PDF.
 * @param {Object} po - The purchase order from the DB
 * @param {Array} lineItems - Line items with title, sku, ordered_qty, unit_cost
 * @returns {Promise<Buffer>} PDF buffer
 */
function generatePO(po, lineItems) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const buffers = [];
    doc.on('data', chunk => buffers.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(buffers)));
    // PDFKit failures (e.g. a glyph Helvetica can't render) surface as
    // 'error' events or synchronous throws. Without this the promise never
    // settles and the send route hangs until the client times out.
    doc.on('error', reject);

    try {

    // ─── Header ──────────────────────────────────────────────────────
    doc.fontSize(24).font('Helvetica-Bold').text('PURCHASE ORDER', { align: 'left' });
    doc.moveDown(0.5);

    doc.fontSize(10).font('Helvetica');

    // PO Info (right aligned)
    const poX = doc.page.width - 200;
    doc.text(`PO#: ${po.po_number}`, poX, doc.y, { align: 'right' });
    doc.text(`Date: ${new Date(po.created_at).toLocaleDateString()}`, { align: 'right' });
    doc.text(`Status: ${po.status.toUpperCase()}`, { align: 'right' });
    doc.moveDown(1);

    // ─── Vendor Info ─────────────────────────────────────────────────
    doc.font('Helvetica-Bold').text('VENDOR:', { continued: true });
    doc.font('Helvetica').text(`  ${trunc(po.vendor_name, 60)}`);
    doc.text(`Email: ${trunc(po.vendor_email, 60)}`);
    doc.moveDown(1);

    // ─── Separator ───────────────────────────────────────────────────
    doc.moveTo(50, doc.y)
       .lineTo(doc.page.width - 50, doc.y)
       .stroke();
    doc.moveDown(0.5);

    // ─── Line Items Table ────────────────────────────────────────────
    const tableTop = doc.y;
    const columns = [
      { label: 'SKU', x: 50, width: 100 },
      { label: 'Product', x: 160, width: 200 },
      { label: 'Qty', x: 370, width: 50, align: 'right' },
      { label: 'Unit Cost', x: 430, width: 70, align: 'right' },
      { label: 'Total', x: 500, width: 70, align: 'right' },
    ];

    // Header row
    doc.font('Helvetica-Bold').fontSize(9);
    columns.forEach(col => {
      doc.text(col.label, col.x, tableTop, { width: col.width, align: col.align || 'left' });
    });

    doc.moveDown(0.5);
    doc.moveTo(50, doc.y)
       .lineTo(doc.page.width - 50, doc.y)
       .stroke();
    doc.moveDown(0.3);

    // Data rows
    doc.font('Helvetica').fontSize(9);
    let totalAmount = 0;

    for (const item of lineItems) {
      const y = doc.y;
      const lineTotal = item.ordered_qty * item.unit_cost;
      totalAmount += lineTotal;

      doc.text(trunc(item.sku, 18) || '-', columns[0].x, y, { width: columns[0].width });
      doc.text(trunc(item.title, 60), columns[1].x, y, { width: columns[1].width });
      doc.text(String(item.ordered_qty), columns[2].x, y, { width: columns[2].width, align: 'right' });
      doc.text(`$${Number(item.unit_cost).toFixed(2)}`, columns[3].x, y, { width: columns[3].width, align: 'right' });
      doc.text(`$${lineTotal.toFixed(2)}`, columns[4].x, y, { width: columns[4].width, align: 'right' });

      doc.moveDown(0.8);

      // New page if running out of space
      if (doc.y > doc.page.height - 100) {
        doc.addPage();
      }
    }

    // ─── Total ───────────────────────────────────────────────────────
    doc.moveDown(0.5);
    doc.moveTo(50, doc.y)
       .lineTo(doc.page.width - 50, doc.y)
       .stroke();
    doc.moveDown(0.5);

    doc.font('Helvetica-Bold').fontSize(12);
    doc.text(`TOTAL: $${totalAmount.toFixed(2)}`, { align: 'right' });

    // ─── Notes ───────────────────────────────────────────────────────
    if (po.notes) {
      doc.moveDown(1);
      doc.font('Helvetica-Bold').fontSize(9).text('Notes:');
      doc.font('Helvetica').fontSize(9).text(po.notes);
    }

    doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

module.exports = { generatePO };
